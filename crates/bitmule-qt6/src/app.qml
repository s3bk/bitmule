import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Uploader 1.0

Window {
    visible: true
    width: 480
    height: 720
    title: "File Uploader (Qt6)"

    UploaderApi {
        id: api
        Component.onCompleted: api.init_from_qml()
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 10
        spacing: 10

        // Drop Zone / Folder View
        DropArea {
            Layout.fillWidth: true
            Layout.fillHeight: true
            enabled: !api.is_busy

            onDropped: (drop) => {
                if (drop.hasUrls) {
                    api.add_files(drop.urls)
                }
            }

            Rectangle {
                anchors.fill: parent
                color: parent.containsDrag ? "#e0e0e0" : "#f5f5f5"
                border.color: "#ccc"
                border.width: 1

                ListView {
                    anchors.fill: parent
                    model: api.file_list
                    delegate: ItemDelegate {
                        text: modelData
                        width: parent.width
                    }
                }

                Text {
                    anchors.centerIn: parent
                    text: "Drop files or folders here"
                    visible: api.file_list.length === 0
                    color: "#888"
                }
            }
        }

        // Share Button
        Button {
            text: "Share"
            Layout.fillWidth: true
            enabled: !api.is_busy && api.file_list.length > 0
            onClicked: api.trigger_share()
        }

        // Busy indicator while share is being prepared.
        Text {
            text: "Uploading..."
            visible: api.is_busy
            Layout.alignment: Qt.AlignHCenter
            font.pixelSize: 12
        }

        // Share URL + copy button + QR code, all bound to the same
        // api.share_url. Hidden until a URL exists so an empty state
        // doesn't clutter the layout.
        ColumnLayout {
            Layout.fillWidth: true
            spacing: 6
            visible: api.share_url.length > 0

            RowLayout {
                Layout.fillWidth: true
                spacing: 6

                // Read-only TextField so the URL is selectable +
                // Ctrl-C-copyable. selectByMouse gives drag-select.
                TextField {
                    id: shareUrlField
                    Layout.fillWidth: true
                    text: api.share_url
                    readOnly: true
                    selectByMouse: true
                    font.pixelSize: 12
                    horizontalAlignment: TextInput.AlignLeft
                }

                Button {
                    text: "Copy"
                    onClicked: api.copy_share_url()
                }
            }

            // Scannable QR of the share URL — bound directly to a
            // data:image/svg+xml;base64 URL produced Rust-side.
            Image {
                source: api.qr_data_url
                Layout.alignment: Qt.AlignHCenter
                Layout.preferredWidth: 240
                Layout.preferredHeight: 240
                fillMode: Image.PreserveAspectFit
                smooth: false
            }
        }

        // F00: options panel. Persisted to <config>/bitmule/bitmule-
        // qt6-options.json via api.save_options() on every change.
        GroupBox {
            Layout.fillWidth: true
            title: "Options"
            ColumnLayout {
                anchors.fill: parent
                CheckBox {
                    text: "multi-send by default (keep URL live for more receivers)"
                    checked: api.opt_multi_send
                    onCheckedChanged: {
                        if (api.opt_multi_send !== checked) {
                            api.opt_multi_send = checked;
                            api.save_options();
                        }
                    }
                }
                CheckBox {
                    text: "request UPnP port mapping"
                    checked: api.opt_upnp
                    onCheckedChanged: {
                        if (api.opt_upnp !== checked) {
                            api.opt_upnp = checked;
                            api.save_options();
                        }
                    }
                }
                CheckBox {
                    text: "watch clipboard for bitmule links"
                    checked: api.opt_clipboard_watch
                    onCheckedChanged: {
                        if (api.opt_clipboard_watch !== checked) {
                            api.opt_clipboard_watch = checked;
                            api.save_options();
                        }
                    }
                }
                CheckBox {
                    text: "automatically start downloads from clipboard links"
                    checked: api.opt_auto_download
                    onCheckedChanged: {
                        if (api.opt_auto_download !== checked) {
                            api.opt_auto_download = checked;
                            api.save_options();
                        }
                    }
                }
            }
        }

        // F02: fetch queue — bitmule links detected on the clipboard
        // that aren't own uploads. Row per URL with an "Open" button
        // that hands to the system browser (in-app receiver panel is
        // a follow-up).
        GroupBox {
            Layout.fillWidth: true
            title: "Detected links"
            visible: api.fetch_queue.length > 0
            ColumnLayout {
                anchors.fill: parent
                Repeater {
                    model: api.fetch_queue
                    delegate: RowLayout {
                        Layout.fillWidth: true
                        Label {
                            Layout.fillWidth: true
                            text: modelData
                            elide: Label.ElideMiddle
                            font.pixelSize: 12
                        }
                        Button {
                            text: "Open"
                            onClicked: api.open_fetch_url(modelData)
                        }
                        Button {
                            text: "×"
                            onClicked: api.drop_fetch_url(modelData)
                        }
                    }
                }
            }
        }
    }
}
