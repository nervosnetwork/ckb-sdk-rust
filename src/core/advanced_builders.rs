use ckb_types::{
    constants, core,
    packed::{self, WitnessArgs},
    prelude::*,
};
use derive_getters::Getters;

/// An advanced builder for [`TransactionView`].
///
/// Base on [`packed::TransactionBuilder`] but added lots of syntactic sugar.
///
/// [`TransactionView`]: struct.TransactionView.html
/// [`packed::TransactionBuilder`]: ../packed/struct.TransactionBuilder.html
#[derive(Clone, Debug, Getters)]
pub struct TransactionBuilder {
    #[getter(skip)]
    pub version: packed::Uint32,
    #[getter(rename = "get_cell_deps")]
    pub cell_deps: Vec<packed::CellDep>,
    #[getter(rename = "get_header_deps")]
    pub header_deps: Vec<packed::Byte32>,
    #[getter(rename = "get_inputs")]
    pub inputs: Vec<packed::CellInput>,
    #[getter(rename = "get_outputs")]
    pub outputs: Vec<packed::CellOutput>,
    #[getter(rename = "get_witnesses")]
    pub witnesses: Vec<packed::Bytes>,
    #[getter(rename = "get_outputs_data")]
    pub outputs_data: Vec<packed::Bytes>,
}

/*
 * Implement std traits.
 */
impl ::std::default::Default for TransactionBuilder {
    fn default() -> Self {
        Self {
            version: constants::TX_VERSION.pack(),
            cell_deps: Default::default(),
            header_deps: Default::default(),
            inputs: Default::default(),
            outputs: Default::default(),
            witnesses: Default::default(),
            outputs_data: Default::default(),
        }
    }
}

macro_rules! def_setter_simple {
    (__add_doc, $prefix:ident, $field:ident, $type:ident, $comment:expr) => {
        #[doc = $comment]
        pub fn $field(mut self, v: packed::$type) -> Self {
            self.$prefix.$field = v;
            self
        }
    };
    (__add_doc, $field:ident, $type:ident, $comment:expr) => {
        #[doc = $comment]
        pub fn $field(mut self, v: packed::$type) -> Self {
            self.$field = v;
            self
        }
    };
    ($prefix:ident, $field:ident, $type:ident) => {
        def_setter_simple!(
            __add_doc,
            $prefix,
            $field,
            $type,
            concat!("Sets `", stringify!($prefix), ".", stringify!($field), "`.")
        );
    };
    ($field:ident, $type:ident) => {
        def_setter_simple!(
            __add_doc,
            $field,
            $type,
            concat!("Sets `", stringify!($field), "`.")
        );
    };
}

macro_rules! def_setter_for_vector {
    (
        $prefix:ident, $field:ident, $type:ident,
        $func_push:ident, $func_extend:ident, $func_set:ident,
        $comment_push:expr, $comment_extend:expr, $comment_set:expr,
    ) => {
        #[doc = $comment_push]
        pub fn $func_push(&mut self, v: $prefix::$type) -> &mut Self {
            self.$field.push(v);
            self
        }
        #[doc = $comment_extend]
        pub fn $func_extend<T>(&mut self, v: T) -> &mut Self
        where
            T: ::std::iter::IntoIterator<Item = $prefix::$type>,
        {
            self.$field.extend(v);
            self
        }
        #[doc = $comment_set]
        pub fn $func_set(&mut self, v: Vec<$prefix::$type>) -> &mut Self {
            self.$field = v;
            self
        }
    };
    ($prefix:ident, $field:ident, $type:ident, $func_push:ident, $func_extend:ident, $func_set:ident) => {
        def_setter_for_vector!(
            $prefix,
            $field,
            $type,
            $func_push,
            $func_extend,
            $func_set,
            concat!("Pushes an item into `", stringify!($field), "`."),
            concat!(
                "Extends `",
                stringify!($field),
                "` with the contents of an iterator."
            ),
            concat!("Sets `", stringify!($field), "`."),
        );
    };
    ($field:ident, $type:ident, $func_push:ident, $func_extend:ident, $func_set:ident) => {
        def_setter_for_vector!(packed, $field, $type, $func_push, $func_extend, $func_set);
    };
    (set_i, $field:ident, $type:ident, $func_push:ident, $func_extend:ident, $func_set:ident, $func_set_i: ident) => {
        def_setter_for_vector!(packed, $field, $type, $func_push, $func_extend, $func_set);

        pub fn $func_set_i(&mut self, i: usize, v: packed::$type) -> &mut Self {
            self.$field[i] = v;
            self
        }
    };
}

macro_rules! def_dedup_setter_for_vector {
    (
        $prefix:ident, $field:ident, $type:ident,
        $func_push:ident, $func_extend:ident,
        $comment_push:expr, $comment_extend:expr,
    ) => {
        #[doc = $comment_push]
        pub fn $func_push(&mut self, v: $prefix::$type) -> &mut Self {
            if !self.$field.contains(&v) {
                self.$field.push(v);
            }
            self
        }
        #[doc = $comment_extend]
        pub fn $func_extend<T>(&mut self, v: T) -> &mut Self
        where
            T: ::std::iter::IntoIterator<Item = $prefix::$type>,
        {
            v.into_iter().for_each(|item| {
                if !self.$field.contains(&item) {
                    self.$field.push(item);
                }
            });
            self
        }
    };
    ($prefix:ident, $field:ident, $type:ident, $func_push:ident, $func_extend:ident) => {
        def_dedup_setter_for_vector!(
            $prefix,
            $field,
            $type,
            $func_push,
            $func_extend,
            concat!(
                "Pushes an item into `",
                stringify!($field),
                "` only if the same item is not already in."
            ),
            concat!(
                "Extends `",
                stringify!($field),
                "` with the contents of an iterator, skip already exist ones."
            ),
        );
    };
    ($field:ident, $type:ident, $func_push:ident, $func_extend:ident) => {
        def_dedup_setter_for_vector!(packed, $field, $type, $func_push, $func_extend);
    };
}

impl TransactionBuilder {
    def_setter_simple!(version, Uint32);
    def_setter_for_vector!(cell_deps, CellDep, cell_dep, cell_deps, set_cell_deps);
    def_dedup_setter_for_vector!(cell_deps, CellDep, dedup_cell_dep, dedup_cell_deps);
    def_setter_for_vector!(
        header_deps,
        Byte32,
        header_dep,
        header_deps,
        set_header_deps
    );

    def_dedup_setter_for_vector!(header_deps, Byte32, dedup_header_dep, dedup_header_deps);
    def_setter_for_vector!(inputs, CellInput, input, inputs, set_inputs);
    def_setter_for_vector!(
        set_i,
        outputs,
        CellOutput,
        output,
        outputs,
        set_outputs,
        set_output
    );
    def_setter_for_vector!(
        set_i,
        witnesses,
        Bytes,
        witness,
        witnesses,
        set_witnesses,
        set_witness
    );
    def_setter_for_vector!(
        set_i,
        outputs_data,
        Bytes,
        output_data,
        outputs_data,
        set_outputs_data,
        set_output_data
    );

    fn get_witness_args(&self, i: usize) -> WitnessArgs {
        let witness_data = self.witnesses[i].raw_data();
        if witness_data.is_empty() {
            WitnessArgs::default()
        } else {
            WitnessArgs::from_slice(witness_data.as_ref()).unwrap()
        }
    }

    pub fn set_witness_lock(&mut self, i: usize, v: Option<bytes::Bytes>) -> &mut Self {
        let current_witness = self.get_witness_args(i);
        self.witnesses[i] = current_witness
            .as_builder()
            .lock(v.pack())
            .build()
            .as_bytes()
            .pack();
        self
    }

    /// Converts into [`TransactionView`](struct.TransactionView.html).
    pub fn build(self) -> core::TransactionView {
        let Self {
            version,
            cell_deps,
            header_deps,
            inputs,
            outputs,
            witnesses,
            outputs_data,
        } = self;
        let raw = packed::RawTransaction::new_builder()
            .version(version)
            .cell_deps(cell_deps.pack())
            .header_deps(header_deps.pack())
            .inputs(inputs.pack())
            .outputs(outputs.pack())
            .outputs_data(outputs_data.pack())
            .build();
        let tx = packed::Transaction::new_builder()
            .raw(raw)
            .witnesses(witnesses.pack())
            .build();

        tx.into_view()
    }
}
