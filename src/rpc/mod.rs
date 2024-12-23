mod ckb;
pub mod ckb_indexer;
pub mod ckb_light_client;

use anyhow::anyhow;
pub use ckb::{CkbRpcAsyncClient, CkbRpcClient};
pub use ckb_indexer::{IndexerRpcAsyncClient, IndexerRpcClient};
use ckb_jsonrpc_types::{JsonBytes, ResponseFormat};
pub use ckb_light_client::{LightClientRpcAsyncClient, LightClientRpcClient};

use std::future::Future;
use thiserror::Error;

pub(crate) fn block_on<F: Send>(future: impl Future<Output = F> + Send) -> F {
    match tokio::runtime::Handle::try_current() {
        Ok(h)
            if matches!(
                h.runtime_flavor(),
                tokio::runtime::RuntimeFlavor::MultiThread
            ) =>
        {
            tokio::task::block_in_place(|| h.block_on(future))
        }
        // if we on the current runtime, it must use another thread to poll this future,
        // can't block on current runtime, it will block current reactor to stop forever
        // in tokio runtime, this time will panic
        Ok(_) => std::thread::scope(|s| {
            s.spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(future)
            })
            .join()
            .unwrap()
        }),
        Err(_) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future),
    }
}

#[derive(Error, Debug)]
pub enum RpcError {
    #[error("parse json error: `{0}`")]
    Json(#[from] serde_json::Error),
    #[error("http error: `{0}`")]
    Http(#[from] reqwest::Error),
    #[error("jsonrpc error: `{0}`")]
    Rpc(#[from] jsonrpc_core::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[macro_export]
macro_rules! jsonrpc {
    (
        $(#[$struct_attr:meta])*
        pub struct $struct_name:ident {$(
            $(#[$attr:meta])*
            pub fn $method:ident(& $selff:ident $(, $arg_name:ident: $arg_ty:ty)*)
                -> $return_ty:ty;
        )*}
    ) => (
        $(#[$struct_attr])*
        pub struct $struct_name {
            pub(crate) client: $crate::rpc::RpcClient,
            pub(crate) id: std::sync::atomic::AtomicU64,
        }

        impl Clone for $struct_name {
            fn clone(&self) -> Self {
                Self {
                    client: self.client.clone(),
                    id: 0.into()
                }
            }
        }

        impl $struct_name {
            pub fn new(uri: &str) -> Self {
                $struct_name {  id: 0.into(), client: $crate::rpc::RpcClient::new(uri), }
            }

            pub fn post<PARAM, RET>(&self, method:&str, params: PARAM)->Result<RET, $crate::rpc::RpcError>
            where
                PARAM:serde::ser::Serialize + Send + 'static,
                RET: serde::de::DeserializeOwned + Send + 'static,
            {
                let id = self.id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let params_fn = || -> Result<_,_> {
                    let params = serde_json::to_value(params)?;
                    let mut req_json = serde_json::Map::new();
                    req_json.insert("id".to_owned(), serde_json::json!(id));
                    req_json.insert("jsonrpc".to_owned(), serde_json::json!("2.0"));
                    req_json.insert("method".to_owned(), serde_json::json!(method));
                    req_json.insert("params".to_owned(), params);
                    Ok(req_json)
                };

                let task = self.client.post(params_fn);
                $crate::rpc::block_on(task)

            }

            $(
                $(#[$attr])*
                pub fn $method(&$selff $(, $arg_name: $arg_ty)*) -> Result<$return_ty, $crate::rpc::RpcError> {
                    let method = String::from(stringify!($method));
                    let params = $crate::serialize_parameters!($($arg_name,)*);
                    let id = $selff.id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    let params_fn = || -> Result<_,_> {
                        let mut req_json = serde_json::Map::new();
                        req_json.insert("id".to_owned(), serde_json::json!(id));
                        req_json.insert("jsonrpc".to_owned(), serde_json::json!("2.0"));
                        req_json.insert("method".to_owned(), serde_json::json!(method));
                        req_json.insert("params".to_owned(), params);
                        Ok(req_json)
                    };

                    let task = $selff.client.post(params_fn);
                    $crate::rpc::block_on(task)
                }
            )*
        }
    )
}

#[macro_export]
macro_rules! jsonrpc_async {
    (
        $(#[$struct_attr:meta])*
        pub struct $struct_name:ident {$(
            $(#[$attr:meta])*
            pub fn $method:ident(& $selff:ident $(, $arg_name:ident: $arg_ty:ty)*)
                -> $return_ty:ty;
        )*}
    ) => (
        $(#[$struct_attr])*
        pub struct $struct_name {
            pub(crate) client: $crate::rpc::RpcClient,
            pub(crate) id: std::sync::atomic::AtomicU64,
        }

        impl Clone for $struct_name {
            fn clone(&self) -> Self {
                Self {
                    client: self.client.clone(),
                    id: 0.into()
                }
            }
        }

        impl $struct_name {
            pub fn new(uri: &str) -> Self {
                $struct_name {  id: 0.into(), client: $crate::rpc::RpcClient::new(uri), }
            }

            pub fn post<PARAM, RET>(&self, method:&str, params: PARAM)->impl std::future::Future<Output =Result<RET, $crate::rpc::RpcError>> + Send + 'static
            where
                PARAM:serde::ser::Serialize + Send + 'static,
                RET: serde::de::DeserializeOwned + Send + 'static,
            {
                let id = self.id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let method = serde_json::json!(method);

                let params_fn = move || -> Result<_,_> {
                    let params = serde_json::to_value(params)?;
                    let mut req_json = serde_json::Map::new();
                    req_json.insert("id".to_owned(), serde_json::json!(id));
                    req_json.insert("jsonrpc".to_owned(), serde_json::json!("2.0"));
                    req_json.insert("method".to_owned(), method);
                    req_json.insert("params".to_owned(), params);
                    Ok(req_json)
                };

                self.client.post(params_fn)

            }

            $(
                $(#[$attr])*
                pub fn $method(&$selff $(, $arg_name: $arg_ty)*) -> impl std::future::Future<Output =Result<$return_ty, $crate::rpc::RpcError>> {
                    let id = $selff.id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    let params_fn = move || -> Result<_,_> {
                        let method = String::from(stringify!($method));
                        let params = $crate::serialize_parameters!($($arg_name,)*);
                        let mut req_json = serde_json::Map::new();
                        req_json.insert("id".to_owned(), serde_json::json!(id));
                        req_json.insert("jsonrpc".to_owned(), serde_json::json!("2.0"));
                        req_json.insert("method".to_owned(), serde_json::json!(method));
                        req_json.insert("params".to_owned(), params);
                        Ok(req_json)
                    };

                    $selff.client.post(params_fn)
                }
            )*
        }
    )
}

#[derive(Debug, Clone)]
pub(crate) struct RpcClient {
    client: reqwest::Client,
    url: reqwest::Url,
}

impl RpcClient {
    pub fn new(uri: &str) -> Self {
        let url = reqwest::Url::parse(uri).expect("ckb uri, e.g. \"http://127.0.0.1:8114\"");
        Self {
            client: reqwest::Client::new(),
            url,
        }
    }

    pub fn post<PARAM, RET, T>(
        &self,
        json_post_params: T,
    ) -> impl std::future::Future<Output = Result<RET, crate::rpc::RpcError>>
    where
        PARAM: serde::ser::Serialize + Send + 'static,
        RET: serde::de::DeserializeOwned + Send + 'static,
        T: FnOnce() -> Result<PARAM, crate::rpc::RpcError>,
    {
        let url = self.url.clone();
        let client = self.client.clone();

        async move {
            let resp = client.post(url).json(&json_post_params()?).send().await?;
            let output = resp.json::<jsonrpc_core::response::Output>().await?;
            match output {
                jsonrpc_core::response::Output::Success(success) => {
                    serde_json::from_value(success.result).map_err(Into::into)
                }
                jsonrpc_core::response::Output::Failure(failure) => Err(failure.error.into()),
            }
        }
    }
}

#[macro_export]
macro_rules! serialize_parameters {
    () => ( serde_json::Value::Null );
    ($($arg_name:ident,)+) => ( serde_json::to_value(($($arg_name,)+))?)
}

pub trait ResponseFormatGetter<V> {
    fn get_value(self) -> Result<V, crate::rpc::RpcError>;
    fn get_json_bytes(self) -> Result<JsonBytes, crate::rpc::RpcError>;
}

impl<V> ResponseFormatGetter<V> for ResponseFormat<V> {
    fn get_value(self) -> Result<V, crate::rpc::RpcError> {
        match self.inner {
            ckb_jsonrpc_types::Either::Left(v) => Ok(v),
            ckb_jsonrpc_types::Either::Right(_) => Err(crate::rpc::RpcError::Other(anyhow!(
                "It's a JsonBytes, can't get the inner value directly"
            ))),
        }
    }

    fn get_json_bytes(self) -> Result<JsonBytes, crate::rpc::RpcError> {
        match self.inner {
            ckb_jsonrpc_types::Either::Left(_v) => Err(crate::rpc::RpcError::Other(anyhow!(
                "It's not a JsonBytes, can't get the json bytes directly"
            ))),
            ckb_jsonrpc_types::Either::Right(json_bytes) => Ok(json_bytes),
        }
    }
}

#[cfg(test)]
mod anyhow_tests {
    use anyhow::anyhow;
    #[test]
    fn test_rpc_error() {
        let json_rpc_error = jsonrpc_core::Error {
            code: jsonrpc_core::ErrorCode::ParseError,
            message: "parse error".to_string(),
            data: None,
        };
        let error = super::RpcError::from(json_rpc_error);
        let error = anyhow!(error);
        println!("{}", error)
    }
}
