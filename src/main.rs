extern crate clap;
#[macro_use]
extern crate dyon;
extern crate evdev;
extern crate nix;
extern crate rusty_sandbox;
#[macro_use]
extern crate serde_derive;
extern crate toml;

use std::{env, fs, io};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use nix::unistd;
use evdev::{uinput, Device, Key, AttributeSet, InputEvent, EventType};
use dyon::{error, load_str, Array, Dfn, Lt, Module, Runtime, RustObject, Type, Variable};

macro_rules! module_add {
    ($mod:ident << $fun:ident [$($lt:expr),*] [$($ty:expr),*] $ret:expr) => {
        $mod.add(
            Arc::new(stringify!($fun).into()),
            $fun,
            Dfn { lts: vec![$($lt),*], tys: vec![$($ty),*], ret: $ret, ext: vec![], lazy: &[] }
        )
    }
}

macro_rules! wrap_var {
    (rustobj, $value:expr) => {
        Variable::RustObject(Arc::new(Mutex::new($value)) as RustObject)
    };
    (arr $typ:ident, $value:expr) => {
        Variable::Array(Arc::new($value.into_iter().map(|o| wrap_var!($typ, o)).collect::<Vec<_>>()) as Array)
    };
}

macro_rules! with_unwrapped_device {
    ($thing:expr, $fn:expr) => {
        match $thing {
            &Variable::RustObject(ref o) => {
                let mut guard = o.lock().expect(".lock()");
                let dev = guard.downcast_mut::<Device>().expect("downcast_mut()");
                ($fn)(dev)
            },
            ref x => panic!("What is this?? {:?}", x),
        }
    }
}

enum ScriptSource {
    Expr(String),
    Read(Box<dyn io::Read>),
}

impl ScriptSource {
    fn read(self) -> (String, bool) {
        match self {
            ScriptSource::Expr(s) => (
                format!("fn main() ~ evdevs, uinput {{\n{}\n}}", s.replace(");", ")\n").replace("};", "}\n")),
                true,
            ),
            ScriptSource::Read(mut r) => {
                let mut result = String::new();
                let _ = r.read_to_string(&mut result).expect("read_to_string");
                (result, false)
            },
        }
    }
}

#[derive(Default, Deserialize)]
struct EventsConfig {
    keys: Option<Vec<String>>,
    // TODO: other events
}

#[derive(Default, Deserialize)]
struct ScriptConfig {
    events: EventsConfig,
}

pub struct ScriptInputEvent {
    pub kind: u32,
    pub code: u32,
    pub value: u32,
}

dyon_obj!{ScriptInputEvent { kind, code, value }}

dyon_fn!{fn device_name(obj: RustObject) -> String {
    let mut guard = obj.lock().expect(".lock()");
    let dev = guard.downcast_mut::<Device>().expect(".downcast_mut()");
    dev.name().expect("Device name").to_string()
}}

dyon_fn!{fn next_events(arr: Vec<Variable>) -> Vec<ScriptInputEvent> {
    let mut vec = Vec::new();
    for var in arr.iter() {
        with_unwrapped_device!(var, |dev: &mut Device| {
            for ev in dev.fetch_events().unwrap() {
                vec.push(ScriptInputEvent{
                    kind: ev.event_type().0 as u32,
                    code: ev.code() as u32,
                    value: ev.value() as u32,
                });
            }
        });
    }
    return vec;
}}

dyon_fn!{fn emit_event(obj: RustObject, evt_v: Variable) -> bool {
    let mut guard = obj.lock().expect(".lock()");
    let dev = guard.downcast_mut::<uinput::VirtualDevice>().expect(".downcast_mut()");
    if let Variable::Object(evt) = evt_v {
        match (evt.get(&Arc::new("kind".into())), evt.get(&Arc::new("code".into())), evt.get(&Arc::new("value".into()))) {
            (Some(&Variable::F64(kind, _)), Some(&Variable::F64(code, _)), Some(&Variable::F64(value, _))) => {
                let event = InputEvent::new(EventType(kind as u16), code as u16, value as i32);
                dev.emit(&[event]).expect("uinput write_raw()");
                true
            },
            x => {
                println!("WARNING: emit_event: event {:?} does not contain all of (kind, code, value) or one of them isn't a number {:?}", evt, x);
                false
            },
        }
    } else {
        println!("WARNING: emit_event: event is not an object");
        false
    }
}}

fn run_script(devs: Vec<Device>, uinput: uinput::VirtualDevice, script_name: &str, script: String) {
    let mut module = Module::new();
    module_add!(module << device_name [Lt::Default] [Type::Any] Type::Str);
    module_add!(module << next_events [Lt::Default] [Type::Array(Box::new(Type::Any))] Type::Object);
    module_add!(module << emit_event [Lt::Default, Lt::Default] [Type::Any, Type::Object] Type::Bool);
    error(load_str("stdlib.dyon", Arc::new(include_str!("stdlib.dyon").into()), &mut module));
    error(load_str(script_name, Arc::new(script), &mut module));
    let mut rt = Runtime::new();
    rt.push(wrap_var!(arr rustobj, devs));
    rt.current_stack.push((Arc::new("evdevs".to_string()), rt.stack.len() - 1));
    rt.push(wrap_var!(rustobj, uinput));
    rt.current_stack.push((Arc::new("uinput".to_string()), rt.stack.len() - 1));
    error(rt.run(&Arc::new(module)));
}

fn drop_privileges() {
    if unistd::geteuid().is_root() {
        unistd::setgid(unistd::getgid()).expect("setegid()");
        unistd::setgroups(&[]).expect("setgroups()");
        unistd::chdir("/dev/input".into()).expect("chdir()");
        unistd::chroot("/dev/input".into()).expect("chroot()");
        unistd::setuid(unistd::getuid()).expect("setegid()");
    }
    rusty_sandbox::Sandbox::new().sandbox_this_process();
}

fn main() {
    let matches = clap::App::new("evscript")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Greg V <greg@unrelenting.technology>")
        .about("A tiny sandboxed Dyon scripting environment for evdev input devices.")
        .arg(
            clap::Arg::with_name("FILE")
                .short("f")
                .long("file")
                .takes_value(true)
                .help("The script file to run, by default - (stdin)"),
        )
        .arg(
            clap::Arg::with_name("EXPR")
                .short("e")
                .long("expr")
                .takes_value(true)
                .help("The script expression to run (inside main), overrides the file if present"),
        )
        .arg(
            clap::Arg::with_name("DEV")
                .short("d")
                .long("device")
                .takes_value(true)
                .multiple(true)
                .help("A device to get events from"),
        )
        .get_matches();

    let script_src: ScriptSource = match matches.value_of("EXPR") {
        Some(expr) => ScriptSource::Expr(expr.to_owned()),
        None => match matches.value_of("FILE") {
            Some("-") | None => ScriptSource::Read(Box::new(io::stdin())),
            Some(x) => ScriptSource::Read(Box::new(fs::File::open(x).expect("script open()"))),
        },
    };

    let devs = matches
        .values_of_os("DEV")
        .map(|vs| {
            vs.map(|a| evdev::Device::open(&a).expect("evdev open()"))
                .collect::<Vec<_>>()
        })
        .unwrap_or(Vec::new());

    let (script, is_expr_mode) = script_src.read();

    let script_conf_str = &script
        .lines()
        .take_while(|l| l.starts_with("//!"))
        .map(|l| format!("{}\n", l.trim_start_matches("//!")))
        .collect::<String>();

    let mut keys = AttributeSet::<Key>::new();
    if is_expr_mode {
        // Just allow all keys
        for i in 0..255 {
            keys.insert(Key(i));
        }
    } else {
        let script_conf: ScriptConfig = toml::from_str(script_conf_str).expect("TOML parsing");
        if let Some(str_keys) = script_conf.events.keys {
            for key in str_keys {
                keys.insert(Key::from_str(&format!("KEY_{}", key)).expect("Unknown key in script config"))
            }
        }
    }

    let uinput = uinput::VirtualDeviceBuilder::new().unwrap()
        .name("Virtual keyboard")
        .with_keys(&keys).unwrap()
        .build().unwrap();

    drop_privileges();

    run_script(devs, uinput, matches.value_of("FILE").unwrap_or("-"), script);
}
