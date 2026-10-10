use std::{
    ffi::CString,
    os::raw::{c_char, c_int},
    path::Path,
};

use serde_json::Value;
use uuid::Uuid;

use crate::{management_protocol::ManagementRequest, management_service};

const KEY_DOWN: c_int = 258;
const KEY_UP: c_int = 259;

#[link(name = "ncurses")]
unsafe extern "C" {
    fn initscr() -> *mut libc::c_void;
    fn endwin() -> c_int;
    fn cbreak() -> c_int;
    fn noecho() -> c_int;
    fn keypad(window: *mut libc::c_void, enabled: bool) -> c_int;
    fn erase() -> c_int;
    fn refresh() -> c_int;
    fn getch() -> c_int;
    fn mvaddnstr(y: c_int, x: c_int, value: *const c_char, length: c_int) -> c_int;
}

struct Screen;
impl Screen {
    fn open() -> Result<Self, String> {
        // SAFETY: ncurses owns its global terminal state until Screen is dropped.
        let screen = unsafe { initscr() };
        if screen.is_null() {
            return Err("curses terminal initialization failed".into());
        }
        unsafe {
            cbreak();
            noecho();
            keypad(screen, true);
        }
        Ok(Self)
    }
}
impl Drop for Screen {
    fn drop(&mut self) {
        unsafe {
            endwin();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Page {
    Clients,
    Services(Uuid),
}

#[derive(Debug, Eq, PartialEq)]
struct Navigation {
    selected: usize,
    count: usize,
}
impl Navigation {
    fn new(count: usize) -> Self {
        Self { selected: 0, count }
    }
    fn key(&mut self, key: c_int) {
        match key {
            KEY_UP if self.selected > 0 => self.selected -= 1,
            KEY_DOWN if self.selected + 1 < self.count => self.selected += 1,
            _ => {}
        }
    }
}

pub fn run(socket: &Path) -> Result<(), String> {
    let _screen = Screen::open()?;
    let mut page = Page::Clients;
    let mut selected = 0;
    loop {
        let (title, records) = load(socket, page)?;
        let mut navigation = Navigation::new(records.len());
        navigation.selected = selected.min(records.len().saturating_sub(1));
        draw(&title, &records, navigation.selected);
        let key = unsafe { getch() };
        match key {
            27 | 113 => match page {
                Page::Clients => return Ok(()),
                Page::Services(_) => {
                    page = Page::Clients;
                    selected = 0;
                }
            },
            10 | 13 if !records.is_empty() => match page {
                Page::Clients => {
                    let id = records[navigation.selected]
                        .get("client_id")
                        .and_then(Value::as_str)
                        .ok_or("client record has no client_id")?;
                    page = Page::Services(Uuid::parse_str(id).map_err(|_| "client_id is invalid")?);
                    selected = 0;
                }
                Page::Services(_) => {}
            },
            100 if !records.is_empty() => {
                delete(socket, page, &records[navigation.selected])?;
                selected = navigation.selected.saturating_sub(1);
            }
            _ => {
                navigation.key(key);
                selected = navigation.selected;
            }
        }
    }
}

fn load(socket: &Path, page: Page) -> Result<(String, Vec<Value>), String> {
    let (title, request) = match page {
        Page::Clients => (
            "JWT Clients - Enter: services  d: delete  q: quit".to_owned(),
            ManagementRequest::ListClients,
        ),
        Page::Services(client_id) => (
            format!("Services for {client_id} - d: delete  q: back"),
            ManagementRequest::ListServices { client_id },
        ),
    };
    let response = management_service::request(socket, &request)?;
    if response.status != "SUCCESS" {
        return Err(response
            .error
            .map(|error| error.message)
            .unwrap_or_else(|| "management request failed".into()));
    }
    let records = response
        .result
        .and_then(|value| value.as_array().cloned())
        .ok_or("management list response is invalid")?;
    Ok((title, records))
}

fn delete(socket: &Path, page: Page, record: &Value) -> Result<(), String> {
    let request = match page {
        Page::Clients => ManagementRequest::DeleteClient {
            client_id: uuid_field(record, "client_id")?,
        },
        Page::Services(client_id) => ManagementRequest::DeleteService {
            client_id,
            service_id: uuid_field(record, "service_id")?,
        },
    };
    let response = management_service::request(socket, &request)?;
    if response.status == "SUCCESS" {
        Ok(())
    } else {
        Err(response
            .error
            .map(|error| error.message)
            .unwrap_or_else(|| "delete failed".into()))
    }
}

fn uuid_field(record: &Value, field: &str) -> Result<Uuid, String> {
    Uuid::parse_str(
        record
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{field} is missing"))?,
    )
    .map_err(|_| format!("{field} is invalid"))
}

fn draw(title: &str, records: &[Value], selected: usize) {
    unsafe {
        erase();
    }
    line(
        0,
        2,
        &format!("Autobricks JWT Management {}", crate::VERSION),
    );
    line(2, 2, title);
    if records.is_empty() {
        line(4, 4, "No registered records");
    }
    for (index, record) in records.iter().enumerate() {
        let marker = if index == selected { ">" } else { " " };
        let name = record
            .get("client_name")
            .or_else(|| record.get("service_name"))
            .and_then(Value::as_str)
            .unwrap_or("unnamed");
        let id = record
            .get("client_id")
            .or_else(|| record.get("service_id"))
            .and_then(Value::as_str)
            .unwrap_or("-");
        line(4 + index as i32, 2, &format!("{marker} {name:<28} {id}"));
    }
    unsafe {
        refresh();
    }
}

fn line(y: i32, x: i32, value: &str) {
    let sanitized = value.replace('\0', "?");
    let value = CString::new(sanitized).expect("NUL removed");
    unsafe {
        mvaddnstr(
            y,
            x,
            value.as_ptr(),
            value.as_bytes().len().min(i32::MAX as usize) as i32,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn arrow_navigation_is_bounded() {
        let mut navigation = Navigation::new(3);
        navigation.key(KEY_UP);
        assert_eq!(navigation.selected, 0);
        navigation.key(KEY_DOWN);
        navigation.key(KEY_DOWN);
        navigation.key(KEY_DOWN);
        assert_eq!(navigation.selected, 2);
    }
}
