import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Uploader 1.0

Window {
    visible: true
    width: 520
    height: 780
    title: "bit mule (Qt6)"

    UploaderApi {
        id: api
        Component.onCompleted: api.init_from_qml()
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 10
        spacing: 10

        // ---------- Tab bar ----------
        TabBar {
            id: bar
            Layout.fillWidth: true
            TabButton { text: "Send" }
            TabButton { text: "Receive" }
        }

        StackLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: bar.currentIndex

            // ---------- Send tab ----------
            ColumnLayout {
                spacing: 10

                DropArea {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    enabled: !api.is_busy

                    onDropped: (drop) => {
                        if (drop.hasUrls) api.add_files(drop.urls)
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

                Button {
                    text: "Share"
                    Layout.fillWidth: true
                    enabled: !api.is_busy && api.file_list.length > 0
                    onClicked: api.trigger_share()
                }

                Text {
                    text: "Uploading..."
                    visible: api.is_busy
                    Layout.alignment: Qt.AlignHCenter
                    font.pixelSize: 12
                }

                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 6
                    visible: api.share_url.length > 0

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: 6
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

                    Image {
                        source: api.qr_data_url
                        Layout.alignment: Qt.AlignHCenter
                        Layout.preferredWidth: 240
                        Layout.preferredHeight: 240
                        fillMode: Image.PreserveAspectFit
                        smooth: false
                    }
                }

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
                                    api.opt_multi_send = checked
                                    api.save_options()
                                }
                            }
                        }
                        CheckBox {
                            text: "request UPnP port mapping"
                            checked: api.opt_upnp
                            onCheckedChanged: {
                                if (api.opt_upnp !== checked) {
                                    api.opt_upnp = checked
                                    api.save_options()
                                }
                            }
                        }
                        CheckBox {
                            text: "watch clipboard for bitmule links"
                            checked: api.opt_clipboard_watch
                            onCheckedChanged: {
                                if (api.opt_clipboard_watch !== checked) {
                                    api.opt_clipboard_watch = checked
                                    api.save_options()
                                }
                            }
                        }
                        CheckBox {
                            text: "automatically start downloads from clipboard links"
                            checked: api.opt_auto_download
                            onCheckedChanged: {
                                if (api.opt_auto_download !== checked) {
                                    api.opt_auto_download = checked
                                    api.save_options()
                                }
                            }
                        }
                    }
                }
            }

            // ---------- Receive tab ----------
            ColumnLayout {
                spacing: 10

                RowLayout {
                    Layout.fillWidth: true
                    spacing: 6
                    TextField {
                        id: recvUrlField
                        Layout.fillWidth: true
                        placeholderText: "paste bitmule URL (https://bitmule.qdat.net/#…)"
                        font.pixelSize: 12
                    }
                    Button {
                        text: "Fetch"
                        enabled: recvUrlField.text.length > 0
                        onClicked: {
                            api.add_recv_url(recvUrlField.text)
                            recvUrlField.text = ""
                        }
                    }
                    Button {
                        text: "Open folder"
                        onClicked: api.open_recv_dir()
                    }
                }

                GroupBox {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    title: api.recv_transfers.length > 0
                        ? "Transfers (" + api.recv_transfers.length + ")"
                        : "No transfers yet"

                    ListView {
                        anchors.fill: parent
                        model: api.recv_transfers
                        spacing: 6
                        delegate: Rectangle {
                            width: ListView.view.width
                            height: contentCol.implicitHeight + 12
                            color: "#fafafa"
                            border.color: "#e0e0e0"
                            border.width: 1
                            radius: 4

                            property var entry: JSON.parse(modelData || "{}")

                            ColumnLayout {
                                id: contentCol
                                anchors.fill: parent
                                anchors.margins: 6
                                spacing: 3

                                RowLayout {
                                    Layout.fillWidth: true
                                    Label {
                                        Layout.fillWidth: true
                                        elide: Label.ElideRight
                                        font.pixelSize: 12
                                        font.bold: true
                                        text: entry.name && entry.name.length > 0
                                            ? entry.name
                                            : "(receiving…)"
                                    }
                                    Label {
                                        font.pixelSize: 11
                                        color: "#666"
                                        text: entry.status || "unknown"
                                    }
                                    Button {
                                        text: "×"
                                        onClicked: api.drop_recv_transfer(entry.url)
                                    }
                                }
                                Label {
                                    Layout.fillWidth: true
                                    elide: Label.ElideMiddle
                                    font.pixelSize: 10
                                    color: "#888"
                                    text: entry.url || ""
                                }
                                // Progress bar. Once complete, draggable
                                // Rectangle overlays it — see below.
                                ProgressBar {
                                    Layout.fillWidth: true
                                    from: 0; to: 1
                                    value: entry.progress || 0
                                    visible: entry.status !== "error"
                                }
                                Label {
                                    Layout.fillWidth: true
                                    visible: entry.status === "error"
                                    color: "#c00"
                                    font.pixelSize: 11
                                    text: entry.error || ""
                                    wrapMode: Label.WordWrap
                                }
                                // File drag-out surface (Qt.Drag). On
                                // complete, click-hold + drag to another
                                // app; MIME type text/uri-list.
                                Item {
                                    Layout.fillWidth: true
                                    visible: entry.status === "complete" && entry.path
                                    Layout.preferredHeight: 30
                                    Rectangle {
                                        anchors.fill: parent
                                        color: dragMouse.pressed ? "#dceefe" : "#e8f5e9"
                                        border.color: "#a5d6a7"
                                        border.width: 1
                                        radius: 3
                                        Label {
                                            anchors.centerIn: parent
                                            text: "✓ " + (entry.path || "") + "  (drag me)"
                                            font.pixelSize: 11
                                            color: "#2e7d32"
                                        }
                                    }
                                    MouseArea {
                                        id: dragMouse
                                        anchors.fill: parent
                                        drag.target: dragProxy
                                        onReleased: dragProxy.Drag.drop()
                                    }
                                    Item {
                                        id: dragProxy
                                        Drag.active: dragMouse.drag.active
                                        Drag.dragType: Drag.Automatic
                                        Drag.mimeData: {
                                            "text/uri-list": "file://" + (entry.path || ""),
                                            "text/plain": (entry.path || "")
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Detected-links block sits below both tabs — visible whenever
    // the clipboard watcher has something in the queue, regardless
    // of current tab. Clicking a row here adds it to the recv queue.
    GroupBox {
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.margins: 10
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
                        font.pixelSize: 11
                    }
                    Button {
                        text: "Fetch"
                        onClicked: {
                            api.add_recv_url(modelData)
                            api.drop_fetch_url(modelData)
                        }
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
