use std::fmt;

use serde::{ser, Serialize};

use super::{seq::SerializeSeq, struct_::SerializeStruct};
use super::{Error, Result, Serializer, Unreachable};

pub struct SerializeMap<'serializer, 'indent> {
    ser: &'serializer mut Serializer<'indent>,
    first: bool,
}

impl<'serializer, 'indent: 'serializer> SerializeMap<'serializer, 'indent> {
    pub(crate) fn new(ser: &'serializer mut Serializer<'indent>) -> Self {
        SerializeMap { ser, first: true }
    }
}

impl<'serializer, 'indent: 'serializer> ser::SerializeMap for SerializeMap<'serializer, 'indent> {
    type Ok = ();
    type Error = Error;

    fn end(self) -> Result<Self::Ok> {
        self.ser.current_indent -= 1;
        if !self.first {
            self.ser.buf.push(b'\n');
            self.ser.indent()?;
        }
        self.ser.buf.push(b'}');
        Ok(())
    }

    fn serialize_key<T: ?Sized>(&mut self, key: &T) -> Result<()>
    where
        T: ser::Serialize,
    {
        if !self.first {
            self.ser.buf.push(b',');
        }
        self.first = false;
        self.ser.buf.push(b'\n');
        self.ser.indent()?;

        // Use key serializer to unsure key type validity.
        key.serialize(MapKeySerializer { ser: self.ser })?;
        self.ser.buf.extend_from_slice(b": ");
        Ok(())
    }

    fn serialize_value<T: ?Sized>(&mut self, value: &T) -> Result<()>
    where
        T: ser::Serialize,
    {
        value.serialize(&mut *self.ser)?;
        Ok(())
    }
}

/// Wrapper around Serializer that only allows serialization of valid JSON key types (strings).
struct MapKeySerializer<'serializer, 'indent> {
    ser: &'serializer mut Serializer<'indent>,
}

pub(crate) fn key_must_be_a_string() -> Error {
    Error::Custom("JSON object key is required to be a string type.".to_string())
}

macro_rules! serialize_unsigned_key {
    ($self:ident, $N:expr, $v:expr) => {{
        let ser = $self.ser;
        ser.buf.push(b'"');
        let res: Result<Self::Ok> = super::serialize_unsigned!(ser, $N, $v);
        res?;
        ser.buf.push(b'"');
        Ok(())
    }};
}

macro_rules! serialize_signed_key {
    ($self:ident, $N:expr, $v:expr, $ixx:ident, $uxx:ident) => {{
        let ser = $self.ser;
        ser.buf.push(b'"');
        let res: Result<Self::Ok> = super::serialize_signed!(ser, $N, $v, $ixx, $uxx);
        res?;
        ser.buf.push(b'"');
        Ok(())
    }};
}

impl<'serializer, 'indent: 'serializer> ser::Serializer for MapKeySerializer<'serializer, 'indent> {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = SerializeSeq<'serializer, 'indent>;
    type SerializeTuple = SerializeSeq<'serializer, 'indent>;
    type SerializeTupleStruct = Unreachable;
    type SerializeTupleVariant = Unreachable;
    type SerializeMap = SerializeMap<'serializer, 'indent>;
    type SerializeStruct = SerializeStruct<'serializer, 'indent>;
    type SerializeStructVariant = SerializeStruct<'serializer, 'indent>;

    fn serialize_bool(self, _value: bool) -> Result<()> {
        Err(key_must_be_a_string())
    }
    #[inline]
    fn serialize_str(self, value: &str) -> Result<()> {
        self.ser.serialize_str(value)
    }

    #[inline]
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<()> {
        self.ser.serialize_str(variant)
    }

    #[inline]
    fn serialize_newtype_struct<T>(self, _name: &'static str, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self)
    }

    fn serialize_i8(self, value: i8) -> Result<()> {
        serialize_signed_key!(self, 4, value, i8, u8)
    }

    fn serialize_i16(self, value: i16) -> Result<()> {
        serialize_signed_key!(self, 6, value, i16, u16)
    }

    fn serialize_i32(self, value: i32) -> Result<()> {
        serialize_signed_key!(self, 11, value, i32, u32)
    }

    fn serialize_i64(self, value: i64) -> Result<()> {
        serialize_signed_key!(self, 20, value, i64, u64)
    }

    fn serialize_i128(self, value: i128) -> Result<()> {
        serialize_signed_key!(self, 40, value, i128, u128)
    }

    fn serialize_u8(self, value: u8) -> Result<()> {
        serialize_unsigned_key!(self, 3, value)
    }

    fn serialize_u16(self, value: u16) -> Result<()> {
        serialize_unsigned_key!(self, 5, value)
    }

    fn serialize_u32(self, value: u32) -> Result<()> {
        serialize_unsigned_key!(self, 10, value)
    }

    fn serialize_u64(self, value: u64) -> Result<()> {
        serialize_unsigned_key!(self, 20, value)
    }

    fn serialize_u128(self, value: u128) -> Result<()> {
        serialize_unsigned_key!(self, 39, value)
    }

    fn serialize_f32(self, _value: f32) -> Result<()> {
        Err(key_must_be_a_string())
    }

    fn serialize_f64(self, _value: f64) -> Result<()> {
        Err(key_must_be_a_string())
    }

    fn serialize_char(self, value: char) -> Result<()> {
        self.ser.serialize_str(&value.to_string())
    }

    fn serialize_bytes(self, _value: &[u8]) -> Result<()> {
        Err(key_must_be_a_string())
    }

    fn serialize_unit(self) -> Result<()> {
        Err(key_must_be_a_string())
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<()> {
        Err(key_must_be_a_string())
    }

    fn serialize_newtype_variant<T>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        Err(key_must_be_a_string())
    }

    fn serialize_none(self) -> Result<()> {
        Err(key_must_be_a_string())
    }

    fn serialize_some<T>(self, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        Err(key_must_be_a_string())
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq> {
        Err(key_must_be_a_string())
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple> {
        Err(key_must_be_a_string())
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct> {
        Err(key_must_be_a_string())
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        Err(key_must_be_a_string())
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap> {
        Err(key_must_be_a_string())
    }

    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<Self::SerializeStruct> {
        Err(key_must_be_a_string())
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        Err(key_must_be_a_string())
    }

    fn collect_str<T>(self, _value: &T) -> Result<()>
    where
        T: ?Sized + fmt::Display,
    {
        unreachable!()
    }
}
