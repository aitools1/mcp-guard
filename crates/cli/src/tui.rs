use std::io;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use crossterm::{
    event::{self, Event as CtEvent, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use mcp_guard_core::config::GuardConfig;
use mcp_guard_core::events::{Event, EventLog};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame, Terminal,
};
use sysinfo::System;

// btop-ish dark palette.
const BG: Color = Color::Rgb(24, 26, 32);
const BORDER: Color = Color::Rgb(58, 68, 92);
const FG: Color = Color::Rgb(200, 205, 215);
const DIM: Color = Color::Rgb(120, 125, 140);
const ACCENT: Color = Color::Rgb(110, 180, 255);
const GREEN: Color = Color::Rgb(86, 200, 120);
const YELLOW: Color = Color::Rgb(230, 190, 60);
const RED: Color = Color::Rgb(235, 82, 82);

#[derive(PartialEq, Clone, Copy, Debug)]
enum Focus {
    Servers,
    Log,
}

struct ServerState {
    name: String,
    disabled: Vec<String>,
    /// Server type: "stdio" or "remote"
    server_type: String,
    // Live data (event + sysinfo driven).
    running: bool,
    proxy_pid: Option<u32>,
    child_pid: Option<u32>,
    cpu: u64,
    mem: u64,
    est_tokens: Option<usize>,
    known_tools: Vec<String>,
    expanded: bool,
}

struct LogLine {
    ts_ms: u64,
    kind: LogKind,
    text: String,
}

#[derive(Clone, Copy, PartialEq)]
enum LogKind {
    Started,
    Stopped,
    Tools,
    CallOk,
    CallBlocked,
    Secret,
    Raw,
}

impl From<&Event> for LogKind {
    fn from(e: &Event) -> Self {
        match e {
            Event::ServerStarted { .. } => Self::Started,
            Event::ServerStopped { .. } => Self::Stopped,
            Event::ToolsListed { .. } => Self::Tools,
            Event::ToolCalled { .. } => match e {
                Event::ToolCalled { status, .. } if *status == mcp_guard_core::events::CallStatus::Blocked => {
                    Self::CallBlocked
                }
                _ => Self::CallOk,
            },
            Event::SecretRedacted { .. } => Self::Secret,
        }
    }
}

struct App {
    config_path: PathBuf,
    cfg: Option<GuardConfig>,
    config_error: Option<String>,
    servers: Vec<ServerState>,
    focus: Focus,
    sel: usize,
    log_scroll: usize,
    log: Vec<LogLine>,
    secret_total: usize,
    events_path: Option<PathBuf>,
    events_offset: u64,
    sys: System,
    tick: u64,
    flash: Option<u64>,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn fmt_age(ts_ms: u64) -> String {
    let age = now_ms().saturating_sub(ts_ms) / 1000;
    if age < 60 {
        format!("{age}s")
    } else if age < 3600 {
        format!("{}m", age / 60)
    } else {
        format!("{}h", age / 3600)
    }
}

fn fmt_mem(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / 1024.0 / 1024.0)
    } else {
        format!("{} KB", bytes / 1024)
    }
}

impl App {
    fn new(config_path: PathBuf) -> Self {
        let mut sys = System::new();
        sys.refresh_processes(
            sysinfo::ProcessesToUpdate::All,
            false,
        );
        let (cfg, config_error) = match GuardConfig::from_file(
            config_path.to_string_lossy().as_ref(),
        ) {
            Ok(c) => (Some(c), None),
            Err(e) => (None, Some(e.to_string())),
        };
        let servers = cfg
            .as_ref()
            .map(|c| {
                let mut names: Vec<String> = c.server.keys().cloned().collect();
                names.sort();
                names
                    .into_iter()
                    .map(|name| {
                        let (disabled, server_type) = c.server.get(&name).map(|s| match s {
                            mcp_guard_core::config::ServerConfig::Stdio { disabled_tools, .. } => (disabled_tools.clone(), "stdio".to_string()),
                            mcp_guard_core::config::ServerConfig::Remote { disabled_tools, .. } => (disabled_tools.clone(), "remote".to_string()),
                        }).unwrap_or((Vec::new(), "stdio".to_string()));
                        ServerState {
                            name,
                            disabled,
                            server_type,
                            running: false,
                            proxy_pid: None,
                            child_pid: None,
                            cpu: 0,
                            mem: 0,
                            est_tokens: None,
                            known_tools: Vec::new(),
                            expanded: false,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        let events_path = EventLog::resolve_path();
        Self {
            config_path,
            cfg,
            config_error,
            servers,
            focus: Focus::Servers,
            sel: 0,
            log_scroll: 0,
            log: Vec::new(),
            secret_total: 0,
            events_path,
            events_offset: 0,
            sys,
            tick: 0,
            flash: None,
        }
    }

    /// Left-panel rows: server rows + expanded tool rows (only for stdio servers).
    fn rows(&self) -> Vec<(usize, RowKind)> {
        let mut rows: Vec<(usize, RowKind)> = Vec::new();
        for (i, s) in self.servers.iter().enumerate() {
            rows.push((i, RowKind::Server(i)));
            if s.expanded && s.server_type == "stdio" {
                for t in &s.known_tools {
                    rows.push((i, RowKind::Tool(t.clone())));
                }
                if s.known_tools.is_empty() {
                    rows.push((i, RowKind::NoTools));
                }
            }
        }
        rows
    }

    fn apply_event(&mut self, ev: &Event) {
        match ev {
            Event::ServerStarted {
                ts_ms,
                server,
                proxy_pid,
                child_pid,
            } => {
                if let Some(s) = self.servers.iter_mut().find(|s| &s.name == server) {
                    s.running = true;
                    s.proxy_pid = Some(*proxy_pid);
                    s.child_pid = Some(*child_pid);
                }
                self.log.push(LogLine {
                    ts_ms: *ts_ms,
                    kind: LogKind::Started,
                    text: format!("server '{server}' started"),
                });
            }
            Event::ServerStopped { ts_ms, server } => {
                if let Some(s) = self.servers.iter_mut().find(|s| &s.name == server) {
                    s.running = false;
                    s.proxy_pid = None;
                    s.child_pid = None;
                }
                self.log.push(LogLine {
                    ts_ms: *ts_ms,
                    kind: LogKind::Stopped,
                    text: format!("server '{server}' stopped"),
                });
            }
            Event::ToolsListed {
                ts_ms,
                server,
                tools,
                est_tokens,
                names,
                ..
            } => {
                if let Some(s) = self.servers.iter_mut().find(|s| &s.name == server) {
                    s.est_tokens = Some(*est_tokens);
                    if !names.is_empty() {
                        s.known_tools = names.clone();
                    }
                }
                self.log.push(LogLine {
                    ts_ms: *ts_ms,
                    kind: LogKind::Tools,
                    text: format!("'{server}' listed {tools} tools (~{est_tokens} tokens)"),
                });
            }
            Event::ToolCalled {
                ts_ms,
                server,
                tool,
                latency_ms,
                status,
            } => {
                let kind = if *status == mcp_guard_core::events::CallStatus::Blocked {
                    LogKind::CallBlocked
                } else {
                    LogKind::CallOk
                };
                self.log.push(LogLine {
                    ts_ms: *ts_ms,
                    kind,
                    text: if *status == mcp_guard_core::events::CallStatus::Blocked {
                        format!("'{server}/{tool}' BLOCKED (disabled)")
                    } else {
                        format!("'{server}/{tool}' ok ({latency_ms} ms)")
                    },
                });
            }
            Event::SecretRedacted {
                ts_ms,
                server,
                secret_type,
            } => {
                self.secret_total += 1;
                self.log.push(LogLine {
                    ts_ms: *ts_ms,
                    kind: LogKind::Secret,
                    text: format!("'{server}': secret {secret_type} REDACTED"),
                });
            }
        }
        if self.log.len() > 500 {
            let excess = self.log.len() - 500;
            self.log.drain(..excess);
        }
    }

    fn poll_events(&mut self) {
        let Some(path) = self.events_path.clone() else {
            return;
        };
        let Ok(mut file) = std::fs::File::open(&path) else {
            return;
        };
        let Ok(meta) = file.metadata() else {
            return;
        };
        if meta.len() < self.events_offset {
            // File was rotated/truncated: re-read from the start.
            self.events_offset = 0;
            self.log.clear();
        }
        use std::io::{Read, Seek, SeekFrom};
        let _ = file.seek(SeekFrom::Start(self.events_offset));
        let mut chunk = Vec::new();
        if file.read_to_end(&mut chunk).is_err() {
            return;
        }
        let text = String::from_utf8_lossy(&chunk);
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Event>(line) {
                Ok(ev) => self.apply_event(&ev),
                Err(_) => {
                    self.log.push(LogLine {
                        ts_ms: now_ms(),
                        kind: LogKind::Raw,
                        text: line.to_string(),
                    });
                }
            }
        }
        self.events_offset += chunk.len() as u64;
    }

    fn refresh_metrics(&mut self) {
        for s in self.servers.iter_mut() {
            s.cpu = 0;
            s.mem = 0;
            for pid in [s.proxy_pid, s.child_pid].into_iter().flatten() {
                if let Some(p) = self.sys.process(sysinfo::Pid::from_u32(pid)) {
                    s.cpu += p.cpu_usage() as u64;
                    s.mem += p.memory();
                }
            }
        }
    }

    fn save_config(&mut self) -> Result<()> {
        let mut cfg = self
            .cfg
            .clone()
            .ok_or_else(|| anyhow::anyhow!("config not loaded"))?;
        for s in &self.servers {
            if let Some(c) = cfg.server.get_mut(&s.name) {
                match c {
                    mcp_guard_core::config::ServerConfig::Stdio { disabled_tools, .. } => {
                        *disabled_tools = s.disabled.clone();
                    }
                    mcp_guard_core::config::ServerConfig::Remote { disabled_tools, .. } => {
                        *disabled_tools = s.disabled.clone();
                    }
                }
            }
        }
        let toml_out = mcp_guard_core::config::GuardConfig { server: cfg.server }
            .to_toml_string()?;
        std::fs::write(&self.config_path, toml_out)
            .map_err(|e| anyhow::anyhow!("failed to write {}: {e}", self.config_path.display()))?;
        self.flash = Some(self.tick);
        Ok(())
    }

    fn toggle_tool(&mut self, srv_idx: usize, tool: &str) {
        let Some(server) = self.servers.get_mut(srv_idx) else {
            return;
        };
        if let Some(pos) = server.disabled.iter().position(|d| d == tool) {
            server.disabled.remove(pos);
        } else {
            server.disabled.push(tool.to_string());
            server.disabled.sort();
        }
        let _ = self.save_config();
    }

    fn handle_key(&mut self, code: KeyCode, mods: KeyModifiers) {
        if mods.contains(KeyModifiers::CONTROL) {
            return;
        }
        match code {
            KeyCode::Char('q') | KeyCode::Esc => std::process::exit(0),
            KeyCode::Tab => {
                self.focus = match self.focus {
                    Focus::Servers => Focus::Log,
                    Focus::Log => Focus::Servers,
                };
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if self.focus == Focus::Servers {
                    if self.sel > 0 {
                        self.sel -= 1;
                    }
                } else if self.log_scroll > 0 {
                    self.log_scroll = self.log_scroll.min(self.log.len()).saturating_sub(1);
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.focus == Focus::Servers {
                    let rows = self.rows();
                    if self.sel < rows.len().saturating_sub(1) {
                        self.sel += 1;
                    }
                } else if self.log_scroll < self.log.len().saturating_sub(1) {
                    self.log_scroll += 1;
                }
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                if self.focus != Focus::Servers {
                    return;
                }
                let rows = self.rows();
                let Some((srv_idx, kind)) = rows.get(self.sel) else {
                    return;
                };
                let srv_idx = *srv_idx;
                match kind {
                    RowKind::Server(_) => {
                        if let Some(srv) = self.servers.get_mut(srv_idx) {
                            srv.expanded = !srv.expanded;
                        }
                    }
                    RowKind::Tool(name) => {
                        self.toggle_tool(srv_idx, name);
                    }
                    RowKind::NoTools => {
                        if let Some(srv) = self.servers.get_mut(srv_idx) {
                            srv.expanded = false;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn draw(&self, f: &mut Frame) {
        let size = f.area();
        f.render_widget(
            ratatui::widgets::Clear,
            size,
        );
        f.render_widget(
            Block::default().style(Style::default().bg(BG)),
            size,
        );

        if self.config_error.is_some() && self.cfg.is_none() {
            self.draw_error_screen(f, size);
            return;
        }

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Min(4),
                Constraint::Length(1),
            ])
            .split(size);

        self.draw_title(f, chunks[0]);
        self.draw_summary(f, chunks[1]);

        let panes = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
            .split(chunks[2]);
        self.draw_servers(f, panes[0]);
        self.draw_log(f, panes[1]);

        self.draw_footer(f, chunks[3]);
    }

    fn draw_title(&self, f: &mut Frame, area: Rect) {
        let text = Line::from(vec![
            Span::styled(" mcp-guard ", Style::default().bg(ACCENT).fg(Color::Black).add_modifier(Modifier::BOLD)),
            Span::styled(" MCP proxy dashboard", Style::default().fg(DIM)),
        ]);
        let bar = Paragraph::new(text).style(Style::default().bg(BG));
        f.render_widget(bar, area);
    }

    fn draw_summary(&self, f: &mut Frame, area: Rect) {
        let active: usize = self.servers.iter().filter(|s| s.running).count();
        let ram: u64 = self.servers.iter().filter(|s| s.running).map(|s| s.mem).sum();
        let tokens: usize = self
            .servers
            .iter()
            .filter(|s| s.running)
            .filter_map(|s| s.est_tokens)
            .sum();
        let line = Line::from(vec![
            Span::styled(" SUMMARY  ", Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
            Span::styled(
                format!("{active} active"),
                Style::default().fg(GREEN),
            ),
            Span::styled("  ", Style::default().fg(BG)),
            Span::styled("total RAM ", Style::default().fg(DIM)),
            Span::styled(fmt_mem(ram), Style::default().fg(FG)),
            Span::styled("  ", Style::default().fg(BG)),
            Span::styled("tool context ~", Style::default().fg(DIM)),
            Span::styled(format!("{tokens} tok"), Style::default().fg(ACCENT)),
            Span::styled("  ", Style::default().fg(BG)),
            Span::styled("secrets redacted ", Style::default().fg(DIM)),
            Span::styled(
                format!("{}", self.secret_total),
                Style::default().fg(if self.secret_total > 0 { RED } else { DIM }),
            ),
        ]);
        let w = Paragraph::new(line).style(Style::default().bg(BG));
        f.render_widget(w, area);
    }

    fn draw_servers(&self, f: &mut Frame, area: Rect) {
        let rows = self.rows();
        let items: Vec<ListItem> = rows
            .iter()
            .enumerate()
            .map(|(idx, (srv_idx, kind))| {
                let selected = idx == self.sel;
                let highlight = selected && self.focus == Focus::Servers;
                match kind {
                    RowKind::Server(i) => {
                        let s = &self.servers[*i];
                        let (status, status_style) = if s.running {
                            ("RUNNING", Style::default().fg(GREEN).add_modifier(Modifier::BOLD))
                        } else {
                            ("IDLE", Style::default().fg(DIM))
                        };
                        let tokens = s
                            .est_tokens
                            .map(|t| format!("~{t} tok"))
                            .unwrap_or_else(|| "no data".to_string());
                        let highlight = idx == self.sel && self.focus == Focus::Servers;
                        ListLines::server_line(s, status, status_style, tokens, highlight)
                    }
                    RowKind::Tool(name) => {
                        let s = &self.servers[*srv_idx];
                        let disabled = s.disabled.iter().any(|d| d == name);
                        let mark = if disabled { "[x]" } else { "[ ]" };
                        let prefix = if highlight { ">>" } else { "  " };
                        let prefix_style = if highlight {
                            Style::default().fg(ACCENT)
                        } else {
                            Style::default().fg(DIM)
                        };
                        ListItem::new(vec![Line::from(vec![
                            Span::styled(format!("{prefix}  "), prefix_style),
                            Span::styled(mark, Style::default().fg(if disabled { RED } else { DIM })),
                            Span::styled(format!(" {name}"), Style::default().fg(if disabled { RED } else { FG })),
                        ])])
                    }
                    RowKind::NoTools => ListItem::new(vec![Line::from(Span::styled(
                        "      (no tools listed yet — start the server once)",
                        Style::default().fg(DIM),
                    ))]),
                }
            })
            .collect();
        let block = Block::default()
            .title(" SERVERS & TOOLS ")
            .title_style(Style::default().fg(ACCENT))
            .border_style(Style::default().fg(BORDER))
            .borders(Borders::ALL)
            .style(Style::default().bg(BG));
        let list = List::new(items)
            .block(block)
            .highlight_symbol(">>")
            .highlight_style(
                Style::default()
                    .bg(Color::Rgb(40, 46, 60))
                    .add_modifier(Modifier::BOLD),
            );
        f.render_widget(list, area);
    }

    fn draw_log(&self, f: &mut Frame, area: Rect) {
        let visible = area.height as usize;
        let total = self.log.len();
        let start = total.saturating_sub(self.log_scroll).saturating_sub(visible);
        let lines: Vec<Line> = if total == 0 {
            vec![Line::from(Span::styled(
                " Waiting for MCP traffic... Connect an agent via 'mcp-guard run <server>' ",
                Style::default().fg(DIM),
            ))]
        } else {
            self
                .log
                .iter()
                .skip(start)
                .take(visible.max(1))
                .map(|l| {
                    let (prefix, style) = match l.kind {
                        LogKind::Started => ("• ", Style::default().fg(ACCENT)),
                        LogKind::Stopped => ("• ", Style::default().fg(DIM)),
                        LogKind::Tools => ("• ", Style::default().fg(ACCENT)),
                        LogKind::CallOk => ("✓ ", Style::default().fg(GREEN)),
                        LogKind::CallBlocked => ("⚠ ", Style::default().fg(YELLOW).add_modifier(Modifier::BOLD)),
                        LogKind::Secret => ("⚠ ", Style::default().fg(RED).add_modifier(Modifier::BOLD)),
                        LogKind::Raw => ("· ", Style::default().fg(DIM)),
                    };
                    Line::from(vec![
                        Span::styled(format!("[{:<4}] ", fmt_age(l.ts_ms)), Style::default().fg(DIM)),
                        Span::styled(prefix, style),
                        Span::styled(l.text.clone(), style.fg(match l.kind {
                            LogKind::Raw => DIM,
                            _ => FG,
                        })),
                    ])
                })
                .collect()
        };
        let block = Block::default()
            .title(" LIVE TRAFFIC & SECURITY ")
            .title_style(Style::default().fg(ACCENT))
            .border_style(Style::default().fg(BORDER))
            .borders(Borders::ALL)
            .style(Style::default().bg(BG));
        let w = Paragraph::new(lines).block(block);
        f.render_widget(w, area);
    }

    fn draw_footer(&self, f: &mut Frame, area: Rect) {
        let flash = self.flash.is_some_and(|ts| self.tick.saturating_sub(ts) < 8);
        let msg = if flash {
            " config saved "
        } else if let Some(e) = &self.config_error {
            &format!(" config error: {e} ")
        } else {
            ""
        };
        let line = Line::from(vec![
            Span::styled(" tab switch · j/k move · enter/space toggle tool · q quit", Style::default().fg(DIM)),
            Span::styled(msg, Style::default().fg(if flash { GREEN } else { RED })),
        ]);
        f.render_widget(Paragraph::new(line).style(Style::default().bg(BG)), area);
    }

    fn draw_error_screen(&self, f: &mut Frame, area: Rect) {
        let msg = self
            .config_error
            .as_deref()
            .unwrap_or("unknown error");
        let lines = vec![
            Line::from(Span::styled(
                " mcp-guard: configuration error",
                Style::default().fg(RED).add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(format!(" {msg}"), Style::default().fg(FG))),
            Line::from(Span::styled(
                " Run 'mcp-guard import' to generate mcp-guard.toml, or pass --config.",
                Style::default().fg(DIM),
            )),
            Line::from(Span::styled(" Press q to exit.", Style::default().fg(DIM))),
        ];
        let w = Paragraph::new(lines)
            .alignment(Alignment::Center)
            .style(Style::default().bg(BG));
        f.render_widget(w, area);
    }
}

enum RowKind {
    Server(usize),
    Tool(String),
    NoTools,
}

struct ListLines;
impl ListLines {
    fn server_line<'a>(
        s: &'a ServerState,
        status: &'a str,
        status_style: Style,
        tokens: String,
        highlight: bool,
    ) -> ListItem<'a> {
        let prefix = if highlight { ">>" } else { "  " };
        let prefix_style = if highlight {
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(DIM)
        };
        let type_label = match s.server_type.as_str() {
            "remote" => "remote",
            _ => "stdio",
        };
        ListItem::new(vec![Line::from(vec![
            Span::styled(format!("{prefix} "), prefix_style),
            Span::styled(
                format!("{:<12}", s.name),
                Style::default().fg(FG).add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!(" {type_label:<6} "), Style::default().fg(ACCENT)),
            Span::styled(format!(" {status:<8} "), status_style),
            Span::styled(format!(" {tokens}"), Style::default().fg(DIM)),
        ])])
    }
}

pub fn run_tui(config: PathBuf) -> Result<()> {
    let mut app = App::new(config);
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen, crossterm::cursor::Hide)?;

    let result = run_loop(&mut app, &mut terminal);

    // Restore terminal.
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen, crossterm::cursor::Show)?;
    if let Err(e) = result {
        eprintln!("TUI error: {e}");
    }
    Ok(())
}

fn run_loop(app: &mut App, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    loop {
        app.poll_events();
        if app.tick.is_multiple_of(13) {
            app.sys.refresh_processes(sysinfo::ProcessesToUpdate::All, false);
            app.refresh_metrics();
        }
        app.tick += 1;

        terminal.draw(|f| app.draw(f))?;

        let timeout = Duration::from_millis(150);
        if event::poll(timeout)? {
            match event::read()? {
                CtEvent::Key(key) => {
                    app.handle_key(key.code, key.modifiers);
                }
                CtEvent::Resize(_, _) => {}
                _ => {}
            }
        }
    }
}
