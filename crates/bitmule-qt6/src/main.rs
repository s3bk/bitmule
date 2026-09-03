use c_str_macro::c_str;
use qmetaobject::*;
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use url::Url;

// Simulated async share function
async fn share(files: Vec<PathBuf>) -> Url {
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    Url::parse(&format!("https://share.example.com/item/{}", files.len())).unwrap()
}

#[derive(QObject, Default)]
struct UploaderApi {
    base: qt_base_class!(trait QObject),

    // State properties
    is_busy: qt_property!(bool; NOTIFY is_busy_changed),
    share_url: qt_property!(QString; NOTIFY share_url_changed),
    file_list: qt_property!(QStringList; NOTIFY file_list_changed),

    // Signals
    is_busy_changed: qt_signal!(),
    share_url_changed: qt_signal!(),
    file_list_changed: qt_signal!(),

    // Shared paths state
    paths: Rc<RefCell<Vec<PathBuf>>>,

    // Invokable method from QML
    add_files: qt_method!(fn(&mut self, urls: QVariantList)),
    trigger_share: qt_method!(fn(&mut self)),
}

impl UploaderApi {
    fn add_files(&mut self, urls: QVariantList) {
        let mut paths = self.paths.borrow_mut();
        let mut list = self.file_list.clone();

        for url_var in urls.into_iter() {
            let url_str = url_var.to_qstring().to_string();
            // Clean up file:// prefix from Qt URLs
            let clean_path = url_str.trim_start_matches("file://");
            let path = PathBuf::from(clean_path);

            paths.push(path.clone());
            list.push(QString::from(clean_path));
        }

        self.file_list = QStringList::from(list);
        self.file_list_changed();
    }

    fn trigger_share(&mut self) {
        self.is_busy = true;
        self.is_busy_changed();

        let paths = self.paths.borrow().clone();
        let qpointer = QPointer::from(&*self);

        // Run async operation
        qmetaobject::future::execute_async(async move {
            let url = share(paths).await;

            // Update UI safely on main thread
            if let Some(mut api) = qpointer.as_pinned() {
                api.borrow_mut().share_url = QString::from(url.to_string());
                api.borrow_mut().share_url_changed();

                api.borrow_mut().is_busy = false;
                api.borrow_mut().is_busy_changed();
            }
        });
    }
}

#[tokio::main]
async fn main() {
    qml_register_type::<UploaderApi>(c_str!("Uploader"), 1, 0, c_str!("UploaderApi"));

    let mut engine = QmlEngine::new();
    engine.load_data(include_str!("app.qml").into());
    engine.exec();
}
