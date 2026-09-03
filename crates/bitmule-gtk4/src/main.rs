use gtk4::gdk;
use gtk4::gio;
use gtk4::prelude::*;
use gtk4::{
    Application, ApplicationWindow, Button, DropTarget, HeaderBar, Label,
    ListView, Orientation, SignalListItemFactory, SingleSelection, Box as GtkBox,
};
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use url::Url;

// Simulated async share function
async fn share(files: Vec<PathBuf>) -> Url {
    // Simulating network delay
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    Url::parse(&format!("https://share.example.com/item/{}", files.len())).unwrap()
}

#[tokio::main]
async fn main() {
    let app = Application::builder()
        .application_id("org.example.FileUploader")
        .build();

    app.connect_activate(build_ui);
    app.run();
}

fn build_ui(app: &Application) {
    let window = ApplicationWindow::builder()
        .title("File Uploader (GTK4)")
        .application(app)
        .default_width(400)
        .default_height(500)
        .build();

    let main_box = GtkBox::new(Orientation::Vertical, 10);
    main_box.set_margin_top(10);
    main_box.set_margin_bottom(10);
    main_box.set_margin_start(10);
    main_box.set_margin_end(10);

    // Track dropped paths
    let dropped_paths: Rc<RefCell<Vec<PathBuf>>> = Rc::new(RefCell::new(Vec::new()));

    // Model and View for the drop area (acting as a folder list)
    let store = gio::ListStore::new::<gio::File>();
    let selection = SingleSelection::new(Some(store.clone()));

    let factory = SignalListItemFactory::new();
    factory.connect_setup(|_, list_item| {
        let label = Label::new(None);
        list_item.set_child(Some(&label));
    });

    factory.connect_bind(|_, list_item| {
        let list_item = list_item.downcast_ref::<gtk4::ListItem>().unwrap();
        let file = list_item.item().unwrap().downcast::<gio::File>().unwrap();
        let label = list_item.child().unwrap().downcast::<Label>().unwrap();
        label.set_text(&file.parse_name());
    });

    let list_view = ListView::new(Some(selection), Some(factory));
    list_view.set_vexpand(true);

    // Drop Target for files/folders
    let drop_target = DropTarget::new(gio::File::static_type(), gdk::DragAction::COPY);

    let store_clone = store.clone();
    let paths_clone = dropped_paths.clone();
    drop_target.connect_drop(move |_, value, _, _| {
        if let Ok(file) = value.get::<gio::File>() {
            if let Some(path) = file.path() {
                store_clone.append(&file);
                paths_clone.borrow_mut().push(path);
                return true;
            }
        }
        false
    });

    list_view.add_controller(drop_target);

    // Controls
    let share_button = Button::with_label("Share");
    let status_label = Label::new(Some("Drop files/folders above"));

    let paths_for_share = dropped_paths.clone();
    let button_clone = share_button.clone();
    let label_clone = status_label.clone();
    let list_clone = list_view.clone();

    share_button.connect_clicked(move |_| {
        // Freeze UI input
        button_clone.set_sensitive(false);
        list_clone.set_sensitive(false);
        label_clone.set_text("Uploading...");

        let files = paths_for_share.borrow().clone();
        let button_inner = button_clone.clone();
        let label_inner = label_clone.clone();
        let list_inner = list_clone.clone();

        // Spawn Tokio async runtime context
        glib::MainContext::default().spawn_local(async move {
            let result_url = share(files).await;

            // Update UI with returned URL
            label_inner.set_text(&format!("Shared URL: {}", result_url));
            button_inner.set_sensitive(true);
            list_inner.set_sensitive(true);
        });
    });

    main_box.append(&list_view);
    main_box.append(&share_button);
    main_box.append(&status_label);

    window.set_child(Some(&main_box));
    window.present();

}
