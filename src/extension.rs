// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};

use lazy_static::lazy_static;
use serde::de::Error as _;

use crate::appraisal::Appraisal;
use crate::ear::Ear;
use crate::error::Error;
use crate::raw::{RawValue, RawValueKind};

#[derive(Debug, Clone)]
struct ExtensionEntry {
    pub kind: RawValueKind,
    pub value: RawValue,
}

impl ExtensionEntry {
    pub fn new(kind: RawValueKind) -> ExtensionEntry {
        ExtensionEntry {
            kind,
            value: RawValue::Null,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum CollectedKey {
    Key(i32),
    Name(String),
}

#[derive(Debug)]
pub struct Extensions {
    by_key: BTreeMap<i32, Arc<RwLock<ExtensionEntry>>>,
    by_name: BTreeMap<String, Arc<RwLock<ExtensionEntry>>>,
    collected: BTreeMap<CollectedKey, RawValue>,
}

impl Default for Extensions {
    fn default() -> Self {
        Self::new()
    }
}

impl<'de> Extensions {
    pub fn new() -> Extensions {
        Extensions {
            by_key: BTreeMap::new(),
            by_name: BTreeMap::new(),
            collected: BTreeMap::new(),
        }
    }

    pub fn register(&mut self, name: &str, key: i32, kind: RawValueKind) -> Result<(), Error> {
        if self.by_name.contains_key(name) {
            return Err(Error::ExtensionError(
                format!("name {name} already registered").to_string(),
            ));
        }

        if self.by_key.contains_key(&key) {
            return Err(Error::ExtensionError(
                format!("key {key} already registered").to_string(),
            ));
        }

        let entry = Arc::new(RwLock::new(ExtensionEntry::new(kind)));

        // Check whether any of the values we previously collected match the key or name for
        // this entry. If so, add the value to the entry, ensuring it is the right kind.
        // Note: while it is theoretically possible for the collected HashMap to contain both,
        // the key and the name, in practice that won't happen because:
        // - collection only happens during deserialization
        // - a new Extensions is created as part of each deserialization
        // - depending on deserializer.is_human_reaadable, we'd be dealing only with keys or only
        //   with names
        let collected = self
            .collected
            .get(&CollectedKey::Key(key))
            .or(self.collected.get(&CollectedKey::Name(name.to_string())));
        match collected {
            Some(v) => {
                let entry_kind = &entry.read().unwrap().kind.clone();

                if v.is(entry_kind) {
                    entry.write().unwrap().value = v.clone();
                    Ok(())
                } else if v.can_convert(entry_kind) {
                    entry.write().unwrap().value = v.convert(entry_kind)?;
                    Ok(())
                } else {
                    Err(Error::ExtensionError(
                        format!(
                            "kind mismatch: value is {vk:?}, but want {ek:?}",
                            vk = v.kind(),
                            ek = entry.read().unwrap().kind
                        )
                        .to_string(),
                    ))
                }
            }
            None => Ok(()),
        }?;

        self.by_key.insert(key, Arc::clone(&entry));
        self.by_name.insert(name.to_string(), Arc::clone(&entry));

        Ok(())
    }

    pub fn have_key(&self, key: &i32) -> bool {
        self.by_key.contains_key(key)
    }

    pub fn have_name(&self, name: &str) -> bool {
        self.by_name.contains_key(name)
    }

    pub fn get_by_key(&self, key: &i32) -> Option<RawValue> {
        self.by_key
            .get(key)
            .map(|entry| entry.read().unwrap().value.clone())
    }

    pub fn get_by_name(&self, name: &str) -> Option<RawValue> {
        self.by_name
            .get(name)
            .map(|entry| entry.read().unwrap().value.clone())
    }

    pub fn get_kind_by_key(&self, key: &i32) -> RawValueKind {
        match self.by_key.get(key) {
            Some(entry) => entry.read().unwrap().kind.clone(),
            None => RawValueKind::Null,
        }
    }

    pub fn get_kind_by_name(&self, name: &str) -> RawValueKind {
        match self.by_name.get(name) {
            Some(entry) => entry.read().unwrap().kind.clone(),
            None => RawValueKind::Null,
        }
    }

    pub fn set_by_key(&mut self, key: i32, value: RawValue) -> Result<(), Error> {
        let entry = self.by_key.get(&key).ok_or(Error::ExtensionError(
            format!("{key} not registered").to_string(),
        ))?;

        if !value.is(&entry.read().unwrap().kind) {
            return Err(Error::ExtensionError(format!(
                "kind mismatch: value is {vk:?}, but want {ek:?}",
                vk = value.kind(),
                ek = entry.read().unwrap().kind
            )));
        }

        entry.write().unwrap().value = value;

        Ok(())
    }

    pub fn set_by_name(&mut self, name: &str, value: RawValue) -> Result<(), Error> {
        let entry = self.by_name.get_mut(name).ok_or(Error::ExtensionError(
            format!("{name} not registered").to_string(),
        ))?;

        if !value.is(&entry.read().unwrap().kind) {
            return Err(Error::ExtensionError(format!(
                "kind mismatch: value is {vk:?}, but want {ek:?}",
                vk = value.kind(),
                ek = entry.read().unwrap().kind
            )));
        }

        entry.write().unwrap().value = value;

        Ok(())
    }

    pub(crate) fn visit_map_entry_by_name<A>(
        &mut self,
        name: &str,
        mut map: A,
    ) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        if !self.have_name(name) {
            self.collected.insert(
                CollectedKey::Name(name.to_string()),
                map.next_value::<RawValue>()?,
            );
            return Ok(());
        }

        let value = map.next_value::<RawValue>()?;

        self.set_by_name(name, value).map_err(A::Error::custom)?;

        Ok(())
    }

    pub(crate) fn visit_map_entry_by_key<A>(&mut self, key: i32, mut map: A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        if !self.have_key(&key) {
            self.collected
                .insert(CollectedKey::Key(key), map.next_value::<RawValue>()?);
            return Ok(());
        }

        let value = map.next_value::<RawValue>()?;

        self.set_by_key(key, value).map_err(A::Error::custom)?;

        Ok(())
    }

    pub(crate) fn serialize_to_map_by_name<M>(&self, map: &mut M) -> Result<(), M::Error>
    where
        M: serde::ser::SerializeMap,
    {
        for (name, val) in &self.by_name {
            if val.read().unwrap().value.is(&RawValueKind::Null) {
                continue;
            }

            map.serialize_entry(&name, &val.read().unwrap().value)?;
        }

        Ok(())
    }

    pub(crate) fn serialize_to_map_by_key<M>(&self, map: &mut M) -> Result<(), M::Error>
    where
        M: serde::ser::SerializeMap,
    {
        for (key, val) in &self.by_key {
            if val.read().unwrap().value.is(&RawValueKind::Null) {
                continue;
            }

            map.serialize_entry(&key, &val.read().unwrap().value)?;
        }

        Ok(())
    }
}

impl PartialEq for Extensions {
    fn eq(&self, other: &Self) -> bool {
        for (name, val) in &self.by_name {
            match other.get_by_name(name) {
                Some(other_val) => {
                    if val.read().unwrap().value != other_val {
                        return false;
                    }
                }
                None => return false,
            }
        }

        for (key, val) in &self.by_key {
            match other.get_by_key(key) {
                Some(other_val) => {
                    if val.read().unwrap().value != other_val {
                        return false;
                    }
                }
                None => return false,
            }
        }

        true
    }
}

#[derive(Debug, Clone)]
struct RegisterEntry {
    pub name: String,
    pub key: i32,
    pub kind: RawValueKind,
}

#[derive(Debug, Clone)]
struct Register {
    pub entries: Vec<RegisterEntry>,
    names: HashSet<String>,
    keys: HashSet<i32>,
}

impl Register {
    pub fn new() -> Self {
        Register {
            entries: Vec::new(),
            names: HashSet::new(),
            keys: HashSet::new(),
        }
    }

    pub fn register(&mut self, name: &str, key: i32, kind: RawValueKind) -> Result<(), Error> {
        match self.names.get(name) {
            Some(_) => Err(Error::ExtensionError(
                format!("name {name} already registered").to_string(),
            )),
            None => Ok(()),
        }?;

        match self.keys.get(&key) {
            Some(_) => Err(Error::ExtensionError(
                format!("key {key} already registered").to_string(),
            )),
            None => Ok(()),
        }?;

        self.entries.push(RegisterEntry {
            name: name.to_string(),
            key,
            kind,
        });

        Ok(())
    }
}

impl IntoIterator for Register {
    type Item = RegisterEntry;
    type IntoIter = <Vec<RegisterEntry> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

#[derive(Debug, Clone)]
pub struct Profile {
    id: String,
    ear: Register,
    appraisal: Register,
}

impl Profile {
    pub fn new(id: &str) -> Self {
        Profile {
            id: id.to_string(),
            ear: Register::new(),
            appraisal: Register::new(),
        }
    }

    pub fn register_ear_extension(
        &mut self,
        name: &str,
        key: i32,
        kind: RawValueKind,
    ) -> Result<(), Error> {
        self.ear.register(name, key, kind)
    }

    pub fn register_appraisal_extension(
        &mut self,
        name: &str,
        key: i32,
        kind: RawValueKind,
    ) -> Result<(), Error> {
        self.appraisal.register(name, key, kind)
    }

    pub fn populate_ear_extensions(&self, ear: &mut Ear) -> Result<(), Error> {
        if self.id != ear.profile {
            return Err(Error::ProfileError(format!(
                "ID mismatch: wanted {wid}, but got {gid}",
                wid = self.id,
                gid = ear.profile,
            )));
        }

        for entry in self.ear.clone() {
            ear.extensions
                .register(&entry.name, entry.key, entry.kind)?
        }

        for (_, appraisal) in ear.submods.iter_mut() {
            for entry in self.appraisal.clone() {
                appraisal
                    .extensions
                    .register(&entry.name, entry.key, entry.kind)?
            }
        }

        Ok(())
    }

    pub fn populate_appraisal_extensions(&self, appraisal: &mut Appraisal) -> Result<(), Error> {
        for entry in self.appraisal.clone() {
            appraisal
                .extensions
                .register(&entry.name, entry.key, entry.kind)?
        }

        Ok(())
    }
}

lazy_static! {
    static ref PROFILE_REGISTER: Mutex<BTreeMap<String, Profile>> = Mutex::new(BTreeMap::new());
}

pub fn register_profile(profile: &Profile) -> Result<(), Error> {
    let mut register = PROFILE_REGISTER.lock().unwrap();

    match register.get(&profile.id) {
        Some(_) => Err(Error::ProfileError(format!(
            "{id} already registered",
            id = profile.id
        ))),
        None => {
            register.insert(profile.id.clone(), profile.clone());
            Ok(())
        }
    }?;

    Ok(())
}

pub fn get_profile(id: &str) -> Option<Profile> {
    let register = PROFILE_REGISTER.lock().unwrap();
    register.get(id).cloned()
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::base64::Bytes;
    use crate::error::Error;

    use std::str;
    use std::thread;

    use serde::ser::SerializeMap;
    use serde::ser::Serializer;

    #[test]
    fn crud() {
        let mut exts = Extensions::new();
        exts.register("foo", 1, RawValueKind::String).unwrap();

        let res = exts.register("foo", 2, RawValueKind::String);
        assert!(matches!(res, Err(Error::ExtensionError(t))
                if t == "name foo already registered"));

        let res = exts.register("bad", 1, RawValueKind::String);
        assert!(matches!(res, Err(Error::ExtensionError(t))
                if t == "key 1 already registered"));

        assert_eq!(exts.get_kind_by_key(&1), RawValueKind::String);
        assert_eq!(exts.get_kind_by_name("foo"), RawValueKind::String);

        assert!(exts.have_name("foo"));
        assert!(exts.have_key(&1));
        assert!(!exts.have_name("bad"));
        assert!(!exts.have_key(&-1));

        exts.set_by_key(1, RawValue::String("bar".to_string()))
            .unwrap();
        match exts.get_by_name("foo").unwrap() {
            RawValue::String(s) => assert_eq!(s, "bar"),
            v => panic!("unexpected value: {v:?}"),
        }

        exts.set_by_name("foo", RawValue::String("buzz".to_string()))
            .unwrap();
        match exts.get_by_key(&1).unwrap() {
            RawValue::String(s) => assert_eq!(s, "buzz"),
            v => panic!("unexpected value: {v:?}"),
        }

        let res = exts.set_by_name("bad", RawValue::String("bar".to_string()));
        assert!(matches!(res, Err(Error::ExtensionError(t)) if t == "bad not registered"));

        let res = exts.set_by_key(-1, RawValue::String("bar".to_string()));
        assert!(matches!(res, Err(Error::ExtensionError(t)) if t == "-1 not registered"));

        let res = exts.set_by_name("foo", RawValue::Integer(42));
        assert!(matches!(res, Err(Error::ExtensionError(t))
                if t == "kind mismatch: value is Integer, but want String"));

        let res = exts.set_by_key(1, RawValue::Bool(true));
        assert!(matches!(res, Err(Error::ExtensionError(t))
                if t == "kind mismatch: value is Bool, but want String"));
    }

    #[test]
    fn serde() {
        let mut exts = Extensions::new();
        exts.register("foo", 1, RawValueKind::String).unwrap();
        exts.set_by_name("foo", RawValue::String("bar".to_string()))
            .unwrap();

        let mut v = Vec::new();
        let mut s = serde_json::Serializer::new(&mut v);
        let mut map = s.serialize_map(None).unwrap();

        exts.serialize_to_map_by_name(&mut map).unwrap();

        map.end().unwrap();

        let out = str::from_utf8(&v).unwrap();
        assert_eq!(out, r#"{"foo":"bar"}"#);
    }

    #[test]
    fn value_convert() {
        let v = RawValue::String("3q2-7w".to_string());
        let res = v.convert(&RawValueKind::Bytes).unwrap();

        if let RawValue::Bytes(bs) = res {
            let expected: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
            assert_eq!(bs, Bytes::from(&expected[..]));
        } else {
            panic!("wrong variant: {res:?}");
        }
    }

    #[test]
    fn test_send() {
        let mut exts = Extensions::new();
        exts.register("foo", 1, RawValueKind::String).unwrap();
        exts.set_by_name("foo", RawValue::String("test".to_string()))
            .unwrap();

        let handle = thread::spawn(move || {
            let val = match exts.get_by_name("foo").unwrap() {
                RawValue::String(v) => v,
                _ => panic!(),
            };

            assert_eq!(&val, "test");
        });

        handle.join().unwrap();
    }
}
