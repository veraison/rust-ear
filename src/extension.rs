// SPDX-License-Identifier: Apache-2.0

use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::rc::Rc;
use std::sync::Mutex;

use lazy_static::lazy_static;
use serde::de::{Error as _, MapAccess, SeqAccess, Visitor};

use crate::appraisal::Appraisal;
use crate::base64::Bytes;
use crate::ear::Ear;
use crate::error::Error;

/// specifies the type of an ExtensionValue (without requiring a concrete value)
#[derive(Clone, Debug, PartialEq)]
pub enum ExtensionKind {
    Unset,
    Bool,
    String,
    Bytes,
    Integer,
    Float,
    Array,
    Map,
}

/// contains the value of an extension
#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub enum ExtensionValue {
    Unset,
    Bool(bool),
    String(String),
    Bytes(Bytes),
    Integer(i64),
    Float(f64),
    Array(Vec<ExtensionValue>),
    Map(Vec<(ExtensionValue, ExtensionValue)>),
}

impl ExtensionValue {
    pub fn kind(&self) -> ExtensionKind {
        match self {
            ExtensionValue::Unset => ExtensionKind::Unset,
            ExtensionValue::Bool(_) => ExtensionKind::Bool,
            ExtensionValue::String(_) => ExtensionKind::String,
            ExtensionValue::Bytes(_) => ExtensionKind::Bytes,
            ExtensionValue::Integer(_) => ExtensionKind::Integer,
            ExtensionValue::Float(_) => ExtensionKind::Float,
            ExtensionValue::Array(_) => ExtensionKind::Array,
            ExtensionValue::Map(_) => ExtensionKind::Map,
        }
    }

    pub fn is(&self, kind: &ExtensionKind) -> bool {
        self.kind() == *kind
    }

    pub fn can_convert(&self, kind: &ExtensionKind) -> bool {
        matches!(
            (self.kind(), kind),
            (ExtensionKind::String, ExtensionKind::Bytes)
                | (ExtensionKind::Bytes, ExtensionKind::String)
        )
    }

    pub fn convert(&self, kind: &ExtensionKind) -> Result<ExtensionValue, Error> {
        match kind {
            ExtensionKind::Bytes => match self {
                ExtensionValue::String(s) => Ok(ExtensionValue::Bytes(Bytes::try_from(s as &str)?)),
                other => Err(Error::ExtensionError(format!(
                    "cannot convert into {kind:?} from {other:?}",
                ))),
            },
            _ => Err(Error::ExtensionError(format!(
                "cannot convert into {kind:?} from any other variant",
            ))),
        }
    }
}

impl serde::Serialize for ExtensionValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            ExtensionValue::Unset => serializer.serialize_none(),
            ExtensionValue::Bool(v) => serializer.serialize_bool(*v),
            ExtensionValue::String(v) => serializer.serialize_str(v),
            ExtensionValue::Bytes(v) => v.serialize(serializer),
            ExtensionValue::Integer(v) => serializer.serialize_i64(*v),
            ExtensionValue::Float(v) => serializer.serialize_f64(*v),
            ExtensionValue::Array(v) => v.serialize(serializer),
            ExtensionValue::Map(v) => v.serialize(serializer),
        }
    }
}

impl<'de> serde::Deserialize<'de> for ExtensionValue {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<ExtensionValue, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ValueVisitor;

        impl<'de> Visitor<'de> for ValueVisitor {
            type Value = ExtensionValue;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("any valid JSON or CBOR value")
            }

            #[inline]
            fn visit_bool<E>(self, value: bool) -> Result<ExtensionValue, E> {
                Ok(ExtensionValue::Bool(value))
            }

            #[inline]
            fn visit_i64<E>(self, value: i64) -> Result<ExtensionValue, E> {
                Ok(ExtensionValue::Integer(value))
            }

            #[inline]
            fn visit_u64<E>(self, value: u64) -> Result<ExtensionValue, E>
            where
                E: serde::de::Error,
            {
                let v = i64::try_from(value).map_err(E::custom)?;
                Ok(ExtensionValue::Integer(v))
            }

            #[inline]
            fn visit_f64<E>(self, value: f64) -> Result<ExtensionValue, E> {
                Ok(ExtensionValue::Float(value))
            }

            #[inline]
            fn visit_str<E>(self, value: &str) -> Result<ExtensionValue, E>
            where
                E: serde::de::Error,
            {
                self.visit_string(String::from(value))
            }

            #[inline]
            fn visit_string<E>(self, value: String) -> Result<ExtensionValue, E> {
                Ok(ExtensionValue::String(value))
            }

            #[inline]
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E> {
                Ok(ExtensionValue::Bytes(Bytes::from(v)))
            }

            #[inline]
            fn visit_none<E>(self) -> Result<ExtensionValue, E> {
                Ok(ExtensionValue::Unset)
            }

            #[inline]
            fn visit_some<D>(self, deserializer: D) -> Result<ExtensionValue, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                serde::de::Deserialize::deserialize(deserializer)
            }

            #[inline]
            fn visit_unit<E>(self) -> Result<ExtensionValue, E> {
                Ok(ExtensionValue::Unset)
            }

            #[inline]
            fn visit_seq<V>(self, mut visitor: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let mut vec = Vec::new();

                while let Some(elem) = visitor.next_element()? {
                    vec.push(elem);
                }

                Ok(ExtensionValue::Array(vec))
            }

            fn visit_map<V>(self, mut visitor: V) -> Result<ExtensionValue, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut ret = Vec::new();

                while let Some((key, val)) =
                    visitor.next_entry::<ExtensionValue, ExtensionValue>()?
                {
                    ret.push((key, val));
                }

                Ok(ExtensionValue::Map(ret))
            }
        }

        deserializer.deserialize_any(ValueVisitor)
    }
}

#[derive(Debug, Clone)]
struct ExtensionEntry {
    pub kind: ExtensionKind,
    pub value: ExtensionValue,
}

impl ExtensionEntry {
    pub fn new(kind: ExtensionKind) -> ExtensionEntry {
        ExtensionEntry {
            kind,
            value: ExtensionValue::Unset,
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
    by_key: BTreeMap<i32, Rc<RefCell<ExtensionEntry>>>,
    by_name: BTreeMap<String, Rc<RefCell<ExtensionEntry>>>,
    collected: BTreeMap<CollectedKey, ExtensionValue>,
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

    pub fn register(&mut self, name: &str, key: i32, kind: ExtensionKind) -> Result<(), Error> {
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

        let entry = Rc::new(RefCell::new(ExtensionEntry::new(kind)));

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
                let entry_kind = &entry.borrow().kind.clone();

                if v.is(entry_kind) {
                    entry.borrow_mut().value = v.clone();
                    Ok(())
                } else if v.can_convert(entry_kind) {
                    entry.borrow_mut().value = v.convert(entry_kind)?;
                    Ok(())
                } else {
                    Err(Error::ExtensionError(
                        format!(
                            "kind mismatch: value is {vk:?}, but want {ek:?}",
                            vk = v.kind(),
                            ek = entry.borrow().kind
                        )
                        .to_string(),
                    ))
                }
            }
            None => Ok(()),
        }?;

        self.by_key.insert(key, Rc::clone(&entry));
        self.by_name.insert(name.to_string(), Rc::clone(&entry));

        Ok(())
    }

    pub fn have_key(&self, key: &i32) -> bool {
        self.by_key.contains_key(key)
    }

    pub fn have_name(&self, name: &str) -> bool {
        self.by_name.contains_key(name)
    }

    pub fn get_by_key(&self, key: &i32) -> Option<ExtensionValue> {
        self.by_key
            .get(key)
            .map(|entry| entry.borrow().value.clone())
    }

    pub fn get_by_name(&self, name: &str) -> Option<ExtensionValue> {
        self.by_name
            .get(name)
            .map(|entry| entry.borrow().value.clone())
    }

    pub fn get_kind_by_key(&self, key: &i32) -> ExtensionKind {
        match self.by_key.get(key) {
            Some(entry) => entry.borrow().kind.clone(),
            None => ExtensionKind::Unset,
        }
    }

    pub fn get_kind_by_name(&self, name: &str) -> ExtensionKind {
        match self.by_name.get(name) {
            Some(entry) => entry.borrow().kind.clone(),
            None => ExtensionKind::Unset,
        }
    }

    pub fn set_by_key(&mut self, key: i32, value: ExtensionValue) -> Result<(), Error> {
        let entry = self.by_key.get(&key).ok_or(Error::ExtensionError(
            format!("{key} not registered").to_string(),
        ))?;

        if !value.is(&entry.borrow().kind) {
            return Err(Error::ExtensionError(format!(
                "kind mismatch: value is {vk:?}, but want {ek:?}",
                vk = value.kind(),
                ek = entry.borrow().kind
            )));
        }

        entry.borrow_mut().value = value;

        Ok(())
    }

    pub fn set_by_name(&mut self, name: &str, value: ExtensionValue) -> Result<(), Error> {
        let entry = self.by_name.get_mut(name).ok_or(Error::ExtensionError(
            format!("{name} not registered").to_string(),
        ))?;

        if !value.is(&entry.borrow().kind) {
            return Err(Error::ExtensionError(format!(
                "kind mismatch: value is {vk:?}, but want {ek:?}",
                vk = value.kind(),
                ek = entry.borrow().kind
            )));
        }

        entry.borrow_mut().value = value;

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
                map.next_value::<ExtensionValue>()?,
            );
            return Ok(());
        }

        let value = match self.get_kind_by_name(name) {
            ExtensionKind::Unset => Err(A::Error::custom("invalid extension".to_string())),
            ExtensionKind::Bool => Ok(ExtensionValue::Bool(map.next_value::<bool>()?)),
            ExtensionKind::String => Ok(ExtensionValue::String(map.next_value::<String>()?)),
            ExtensionKind::Bytes => Ok(ExtensionValue::Bytes(map.next_value::<Bytes>()?)),
            ExtensionKind::Integer => Ok(ExtensionValue::Integer(map.next_value::<i64>()?)),
            ExtensionKind::Float => Ok(ExtensionValue::Float(map.next_value::<f64>()?)),
            ExtensionKind::Array => Ok(ExtensionValue::Array(
                map.next_value::<Vec<ExtensionValue>>()?,
            )),
            ExtensionKind::Map => Ok(ExtensionValue::Map(
                map.next_value::<Vec<(ExtensionValue, ExtensionValue)>>()?,
            )),
        }?;

        self.set_by_name(name, value).map_err(A::Error::custom)?;

        Ok(())
    }

    pub(crate) fn visit_map_entry_by_key<A>(&mut self, key: i32, mut map: A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        if !self.have_key(&key) {
            self.collected
                .insert(CollectedKey::Key(key), map.next_value::<ExtensionValue>()?);
            return Ok(());
        }

        let value = match self.get_kind_by_key(&key) {
            ExtensionKind::Unset => Err(A::Error::custom("invalid extension".to_string())),
            ExtensionKind::Bool => Ok(ExtensionValue::Bool(map.next_value::<bool>()?)),
            ExtensionKind::String => Ok(ExtensionValue::String(map.next_value::<String>()?)),
            ExtensionKind::Bytes => Ok(ExtensionValue::Bytes(map.next_value::<Bytes>()?)),
            ExtensionKind::Integer => Ok(ExtensionValue::Integer(map.next_value::<i64>()?)),
            ExtensionKind::Float => Ok(ExtensionValue::Float(map.next_value::<f64>()?)),
            ExtensionKind::Array => Ok(ExtensionValue::Array(
                map.next_value::<Vec<ExtensionValue>>()?,
            )),
            ExtensionKind::Map => Ok(ExtensionValue::Map(
                map.next_value::<Vec<(ExtensionValue, ExtensionValue)>>()?,
            )),
        }?;

        self.set_by_key(key, value).map_err(A::Error::custom)?;

        Ok(())
    }

    pub(crate) fn serialize_to_map_by_name<M>(&self, map: &mut M) -> Result<(), M::Error>
    where
        M: serde::ser::SerializeMap,
    {
        for (name, val) in &self.by_name {
            if val.borrow().value.is(&ExtensionKind::Unset) {
                continue;
            }

            map.serialize_entry(&name, &val.borrow().value)?;
        }

        Ok(())
    }

    pub(crate) fn serialize_to_map_by_key<M>(&self, map: &mut M) -> Result<(), M::Error>
    where
        M: serde::ser::SerializeMap,
    {
        for (key, val) in &self.by_key {
            if val.borrow().value.is(&ExtensionKind::Unset) {
                continue;
            }

            map.serialize_entry(&key, &val.borrow().value)?;
        }

        Ok(())
    }
}

impl PartialEq for Extensions {
    fn eq(&self, other: &Self) -> bool {
        for (name, val) in &self.by_name {
            match other.get_by_name(name) {
                Some(other_val) => {
                    if val.borrow().value != other_val {
                        return false;
                    }
                }
                None => return false,
            }
        }

        for (key, val) in &self.by_key {
            match other.get_by_key(key) {
                Some(other_val) => {
                    if val.borrow().value != other_val {
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
    pub kind: ExtensionKind,
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

    pub fn register(&mut self, name: &str, key: i32, kind: ExtensionKind) -> Result<(), Error> {
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
        kind: ExtensionKind,
    ) -> Result<(), Error> {
        self.ear.register(name, key, kind)
    }

    pub fn register_appraisal_extension(
        &mut self,
        name: &str,
        key: i32,
        kind: ExtensionKind,
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
    use crate::error::Error;

    use std::str;

    use serde::ser::SerializeMap;
    use serde::ser::Serializer;

    #[test]
    fn crud() {
        let mut exts = Extensions::new();
        exts.register("foo", 1, ExtensionKind::String).unwrap();

        let res = exts.register("foo", 2, ExtensionKind::String);
        assert!(matches!(res, Err(Error::ExtensionError(t))
                if t == "name foo already registered"));

        let res = exts.register("bad", 1, ExtensionKind::String);
        assert!(matches!(res, Err(Error::ExtensionError(t))
                if t == "key 1 already registered"));

        assert_eq!(exts.get_kind_by_key(&1), ExtensionKind::String);
        assert_eq!(exts.get_kind_by_name("foo"), ExtensionKind::String);

        assert!(exts.have_name("foo"));
        assert!(exts.have_key(&1));
        assert!(!exts.have_name("bad"));
        assert!(!exts.have_key(&-1));

        exts.set_by_key(1, ExtensionValue::String("bar".to_string()))
            .unwrap();
        match exts.get_by_name("foo").unwrap() {
            ExtensionValue::String(s) => assert_eq!(s, "bar"),
            v => panic!("unexpected value: {v:?}"),
        }

        exts.set_by_name("foo", ExtensionValue::String("buzz".to_string()))
            .unwrap();
        match exts.get_by_key(&1).unwrap() {
            ExtensionValue::String(s) => assert_eq!(s, "buzz"),
            v => panic!("unexpected value: {v:?}"),
        }

        let res = exts.set_by_name("bad", ExtensionValue::String("bar".to_string()));
        assert!(matches!(res, Err(Error::ExtensionError(t)) if t == "bad not registered"));

        let res = exts.set_by_key(-1, ExtensionValue::String("bar".to_string()));
        assert!(matches!(res, Err(Error::ExtensionError(t)) if t == "-1 not registered"));

        let res = exts.set_by_name("foo", ExtensionValue::Integer(42));
        assert!(matches!(res, Err(Error::ExtensionError(t))
                if t == "kind mismatch: value is Integer, but want String"));

        let res = exts.set_by_key(1, ExtensionValue::Bool(true));
        assert!(matches!(res, Err(Error::ExtensionError(t))
                if t == "kind mismatch: value is Bool, but want String"));
    }

    #[test]
    fn serde() {
        let mut exts = Extensions::new();
        exts.register("foo", 1, ExtensionKind::String).unwrap();
        exts.set_by_name("foo", ExtensionValue::String("bar".to_string()))
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
        let v = ExtensionValue::String("3q2-7w".to_string());
        let res = v.convert(&ExtensionKind::Bytes).unwrap();

        if let ExtensionValue::Bytes(bs) = res {
            let expected: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
            assert_eq!(bs, Bytes::from(&expected[..]));
        } else {
            panic!("wrong variant: {res:?}");
        }
    }
}
