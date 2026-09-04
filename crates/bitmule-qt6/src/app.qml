import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Uploader 1.0

Window {
    visible: true
    width: 400
    height: 500
    title: "File Uploader (Qt6)"

    UploaderApi {
        id: api
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
    }
}
