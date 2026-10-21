//! Converting between JSON values and Lua values at the sandbox boundary.
//!
//! Both directions are depth-limited, so a cyclic or deeply nested table from a script cannot
//! overflow the host's stack. Tables are read with raw access, so a script's metatables never
//! run on the host's side.

use mlua::{Lua, Table, Value};
use serde_json::{Map, Value as Json};

/// The deepest nesting either direction accepts.
const MAX_DEPTH: usize = 64;
/// The most values a hook's result may hold. Tables can share subtables, so without a budget a
/// small Lua value could expand into a huge JSON tree outside Luau's memory limit.
const MAX_VALUES: usize = 100_000;

/// Builds the Lua value for `value`. With `readonly`, every table is frozen.
pub(super) fn json_to_lua(lua: &Lua, value: &Json, readonly: bool) -> mlua::Result<Value> {
    to_lua(lua, value, readonly, 0)
}

fn to_lua(lua: &Lua, value: &Json, readonly: bool, depth: usize) -> mlua::Result<Value> {
    if depth > MAX_DEPTH {
        return Err(mlua::Error::runtime("JSON nests too deeply"));
    }
    Ok(match value {
        Json::Null => Value::Nil,
        Json::Bool(b) => Value::Boolean(*b),
        Json::Number(n) => Value::Number(n.as_f64().unwrap_or(f64::NAN)),
        Json::String(s) => Value::String(lua.create_string(s)?),
        Json::Array(items) => {
            let table = lua.create_table_with_capacity(items.len(), 0)?;
            for (i, item) in items.iter().enumerate() {
                table.raw_set(i + 1, to_lua(lua, item, readonly, depth + 1)?)?;
            }
            freeze(table, readonly)
        }
        Json::Object(map) => {
            let table = lua.create_table_with_capacity(0, map.len())?;
            for (key, item) in map {
                table.raw_set(key.as_str(), to_lua(lua, item, readonly, depth + 1)?)?;
            }
            freeze(table, readonly)
        }
    })
}

fn freeze(table: Table, readonly: bool) -> Value {
    if readonly {
        table.set_readonly(true);
    }
    Value::Table(table)
}

/// The JSON value of a hook's result. A table with only the keys `1..n` is an array; any other
/// table needs string keys. Functions, userdata and similar values are refused.
pub(super) fn lua_to_json(value: &Value) -> Result<Json, String> {
    to_json(value, 0, &mut { MAX_VALUES })
}

fn to_json(value: &Value, depth: usize, budget: &mut usize) -> Result<Json, String> {
    if depth > MAX_DEPTH {
        return Err("returned tables nest too deeply".to_owned());
    }
    *budget = budget
        .checked_sub(1)
        .ok_or_else(|| format!("returned more than {MAX_VALUES} values"))?;
    match value {
        Value::Nil => Ok(Json::Null),
        Value::Boolean(b) => Ok(Json::Bool(*b)),
        Value::Integer(i) => Ok(Json::from(*i)),
        Value::Number(n) => serde_json::Number::from_f64(*n)
            .map(Json::Number)
            .ok_or_else(|| "returned a number that is not finite".to_owned()),
        Value::String(s) => s
            .to_str()
            .map(|s| Json::String(s.to_owned()))
            .map_err(|_| "returned a string that is not UTF-8".to_owned()),
        Value::Table(table) => table_to_json(table, depth, budget),
        other => Err(format!("returned a {}", other.type_name())),
    }
}

fn table_to_json(table: &Table, depth: usize, budget: &mut usize) -> Result<Json, String> {
    let len = table.raw_len();
    let mut pairs = Vec::new();
    for pair in table.pairs::<Value, Value>() {
        pairs.push(pair.map_err(|e| e.to_string())?);
    }
    if len > 0 && pairs.len() == len {
        let mut items = vec![Json::Null; len];
        for (key, item) in &pairs {
            let index = match key {
                Value::Integer(i) => usize::try_from(*i).ok(),
                Value::Number(n) if n.fract() == 0.0 && *n >= 1.0 => Some(*n as usize),
                _ => None,
            };
            match index.and_then(|i| i.checked_sub(1)).filter(|i| *i < len) {
                Some(i) => items[i] = to_json(item, depth + 1, budget)?,
                None => return Err("returned a table mixing list and named keys".to_owned()),
            }
        }
        return Ok(Json::Array(items));
    }
    let mut map = Map::new();
    for (key, item) in &pairs {
        let Value::String(key) = key else {
            return Err("returned a table mixing list and named keys".to_owned());
        };
        let key = key
            .to_str()
            .map_err(|_| "returned a table key that is not UTF-8".to_owned())?
            .to_owned();
        map.insert(key, to_json(item, depth + 1, budget)?);
    }
    Ok(Json::Object(map))
}
