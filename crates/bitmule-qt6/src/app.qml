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

        // Status / URL Display
        Text {
            text: api.is_busy ? "Uploading..." : (api.share_url ? "Shared URL: " + api.share_url : "")
            Layout.alignment: Qt.AlignHCenter
            font.pixelSize: 12
        }
    }
}
