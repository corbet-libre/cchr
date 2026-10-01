use super::Unique;
use serde::de::{Deserialize, Error, Unexpected, value};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn visitor_numeric_inputs_and_diagnostics_remain_value_free() {
    assert!(Unique::deserialize(value::I64Deserializer::<value::Error>::new(-1)).is_ok());
    assert!(Unique::deserialize(value::F64Deserializer::<value::Error>::new(1.5)).is_ok());
    let error = value::Error::invalid_type(Unexpected::Unit, &Unique);
    assert_eq!(
        error.to_string(),
        "invalid type: unit value, expected JSON without duplicate keys"
    );
}
