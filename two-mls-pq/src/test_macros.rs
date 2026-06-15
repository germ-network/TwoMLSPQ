/// Assert a `Result` is `Ok`, returning the inner value.
///
/// ```ignore
/// let val = assert_ok!(some_result);
/// assert_ok!(some_result, expected_value);
/// ```
#[macro_export]
macro_rules! assert_ok {
    ( $e:expr ) => {
        assert_ok!($e,)
    };

    ( $e:expr, ) => {{
        use std::result::Result::*;
        match $e {
            Ok(v) => v,
            Err(e) => panic!("assertion failed: Err({:?})", e),
        }
    }};

    ( $x:expr, $y:expr $(,)? ) => {
        assert_eq!($x, Ok($y.into()));
    };

    ( $x:expr, $y:expr $(,)?, $($msg:tt)+ ) => {{
        assert_eq!($x, Ok($y.into()), $($msg)+);
    }};
}

/// Assert an `Option` is `Some`, returning the inner value.
///
/// ```ignore
/// let val = assert_some!(some_option);
/// ```
#[macro_export]
macro_rules! assert_some {
    ( $e:expr ) => {
        assert_some!($e,)
    };

    ( $e:expr, ) => {{
        match $e {
            Some(v) => v,
            None => panic!("assertion failed: None"),
        }
    }};
}

/// Assert a `Result` is `Err` matching the given pattern.
///
/// ```ignore
/// assert_err!(some_result, TwoMlsPqError::Mls);
/// assert_err!(some_result, _);
/// ```
#[macro_export]
macro_rules! assert_err {
    ( $x:expr, $y:pat $(,)? ) => {
        assert!(matches!($x, Err($y)))
    };

    ( $x:expr, $y:pat $(,)?, $($msg:tt)+ ) => {{
        assert!(matches!($x, Err($y)), $($msg)+)
    }};
}
