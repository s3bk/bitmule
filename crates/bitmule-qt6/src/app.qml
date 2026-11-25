import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Uploader 1.0

ApplicationWindow {
    id: window
    visible: true
    width: 520
    height: 780
    title: "bit mule (Qt6)"

    // ------------------------------------------------------------------
    // Theme
    //
    // One table of colours, two sets of values (light, dark) and a switch
    // for which set is live: "auto" follows the desktop, "light" and
    // "dark" pin one. Nothing else in this file writes a literal colour
    // except the QR card, which is white in both themes on purpose.
    //
    // The palette is handed to the window as well as used directly, so
    // every Qt Quick Control — buttons, fields, check boxes, tab bar,
    // group boxes, progress bars — is painted from the same table instead
    // of the toolkit's own default light colours.
    // ------------------------------------------------------------------

    SystemPalette { id: systemPalette }

    QtObject {
        id: theme

        // "auto" | "light" | "dark". Rust persists the choice; an options
        // file written before the setting existed reads as "auto".
        readonly property string mode: {
            var m = ("" + api.opt_theme).toLowerCase()
            return (m === "light" || m === "dark") ? m : "auto"
        }
        readonly property int modeIndex: mode === "light" ? 1 : mode === "dark" ? 2 : 0

        // The desktop's own light/dark choice, as best as it can be read
        // without asking the platform. Pale window => light desktop.
        readonly property bool dark: mode === "dark"
            || (mode === "auto" && systemPalette.window.hslLightness < 0.5)

        // Surfaces, from farthest back to closest to the eye.
        readonly property color bg: dark ? "#16181b" : "#f4f5f6"
        readonly property color surface: dark ? "#1e2125" : "#ffffff"
        readonly property color surfaceMuted: dark ? "#24282d" : "#eef0f2"
        readonly property color surfaceHover: dark ? "#26313e" : "#dbe8f7"
        readonly property color accentSoft: dark ? "#23303f" : "#e2edfb"

        readonly property color border: dark ? "#33383e" : "#d3d7dc"
        readonly property color borderStrong: dark ? "#4a5158" : "#b9bfc7"

        // Text, by how much it has to carry.
        readonly property color fg: dark ? "#e7e9ec" : "#1b1d21"
        readonly property color fgMuted: dark ? "#a6acb4" : "#565d66"
        readonly property color fgFaint: dark ? "#7c838c" : "#7f868f"

        readonly property color accent: dark ? "#7aa9ee" : "#2b6bc4"
        readonly property color onAccent: dark ? "#0c131d" : "#ffffff"

        // Outcome colours: success (a finished, draggable file) and error.
        readonly property color okText: dark ? "#86d99b" : "#1f7f3c"
        readonly property color okBg: dark ? "#1c2a21" : "#e8f5ec"
        readonly property color okBorder: dark ? "#35513e" : "#b7dcc3"
        readonly property color danger: dark ? "#ff938a" : "#b3261e"

        // Bevel roles the toolkit uses to draw control outlines.
        readonly property color bevelLight: dark ? "#3a4048" : "#ffffff"
        readonly property color bevelMidlight: dark ? "#313640" : "#f6f7f8"
        readonly property color bevelMid: dark ? "#2a2f35" : "#d3d7dc"
        readonly property color bevelDark: dark ? "#1b1e22" : "#b9bfc7"
        readonly property color bevelShadow: dark ? "#0e1013" : "#8f959d"

        // The QR code is a scanner's contract, not a piece of UI: dark
        // modules on a light field, with a light quiet zone. Inverting it
        // for the dark theme makes many phone apps refuse to read it, so
        // this one stays white in both themes.
        readonly property color qrBackdrop: "#ffffff"
    }

    color: theme.bg

    palette.window: theme.bg
    palette.windowText: theme.fg
    palette.base: theme.surface
    palette.alternateBase: theme.surfaceMuted
    palette.text: theme.fg
    palette.placeholderText: theme.fgFaint
    palette.button: theme.surfaceMuted
    palette.buttonText: theme.fg
    palette.brightText: theme.onAccent
    palette.highlight: theme.accent
    palette.highlightedText: theme.onAccent
    palette.light: theme.bevelLight
    palette.midlight: theme.bevelMidlight
    palette.mid: theme.bevelMid
    palette.dark: theme.bevelDark
    palette.shadow: theme.bevelShadow

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
            TabButton {
                id: tabSend
                text: "Send"
                // The palette-driven style paints an unchecked tab from
                // `dark`/`mid` and writes its label in `brightText`; with a
                // light theme that is white on pale grey. Text roles, not
                // bevel roles, for the two labels.
                palette.brightText: theme.fgMuted
                palette.windowText: theme.fg
            }
            TabButton {
                id: tabRecv
                text: "Receive"
                palette.brightText: theme.fgMuted
                palette.windowText: theme.fg
            }
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
                        color: parent.containsDrag ? theme.surfaceHover : theme.surfaceMuted
                        border.color: parent.containsDrag ? theme.accent : theme.border
                        border.width: 1
                        radius: 6

                        ListView {
                            anchors.fill: parent
                            anchors.margins: 4
                            clip: true
                            model: api.file_list
                            delegate: ItemDelegate {
                                text: modelData
                                width: parent.width
                                font.pixelSize: 12
                            }
                        }

                        Label {
                            anchors.centerIn: parent
                            text: "Drop files or folders here"
                            visible: api.file_list.length === 0
                            color: theme.fgMuted
                            font.pixelSize: 13
                        }
                    }
                }

                Button {
                    id: shareButton
                    text: "Share"
                    Layout.fillWidth: true
                    enabled: !api.is_busy && api.file_list.length > 0
                    onClicked: api.trigger_share()
                }

                Label {
                    text: "Uploading…"
                    visible: api.is_busy
                    Layout.alignment: Qt.AlignHCenter
                    color: theme.fgMuted
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

                    // White card with the code on it — see theme.qrBackdrop.
                    Rectangle {
                        Layout.alignment: Qt.AlignHCenter
                        Layout.preferredWidth: qr.width + 24
                        Layout.preferredHeight: qr.height + 24
                        radius: 8
                        color: theme.qrBackdrop

                        Image {
                            id: qr
                            anchors.centerIn: parent
                            source: api.qr_data_url
                            width: 232
                            height: 232
                            fillMode: Image.PreserveAspectFit
                            smooth: false
                        }
                    }
                }

                GroupBox {
                    Layout.fillWidth: true
                    title: "Options"
                    ColumnLayout {
                        anchors.fill: parent
                        spacing: 4

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

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 8
                            Label {
                                Layout.fillWidth: true
                                text: "colours"
                                color: theme.fg
                                font.pixelSize: 12
                            }
                            ComboBox {
                                id: themeCombo
                                Layout.preferredWidth: 190
                                model: ["Automatic", "Light", "Dark"]
                                // Bound, but the only thing that changes
                                // the setting is this box itself, so the
                                // binding and the pick never disagree.
                                currentIndex: theme.modeIndex
                                onActivated: (index) => {
                                    api.opt_theme = ["auto", "light", "dark"][index]
                                    api.save_options()
                                }
                            }
                        }
                        Label {
                            Layout.fillWidth: true
                            text: "Automatic follows the desktop's light or dark setting."
                            color: theme.fgFaint
                            font.pixelSize: 11
                            wrapMode: Label.WordWrap
                            visible: theme.mode === "auto"
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
                        clip: true
                        delegate: Rectangle {
                            width: ListView.view.width
                            height: contentCol.implicitHeight + 12
                            color: theme.surface
                            border.color: theme.border
                            border.width: 1
                            radius: 6

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
                                        color: theme.fg
                                        text: entry.name && entry.name.length > 0
                                            ? entry.name
                                            : "(receiving…)"
                                    }
                                    Label {
                                        font.pixelSize: 11
                                        color: theme.fgMuted
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
                                    color: theme.fgFaint
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
                                    color: theme.danger
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
                                        color: dragMouse.pressed ? theme.accentSoft : theme.okBg
                                        border.color: dragMouse.pressed ? theme.accent : theme.okBorder
                                        border.width: 1
                                        radius: 4
                                        Label {
                                            anchors.centerIn: parent
                                            text: "✓ " + (entry.path || "") + "  (drag me)"
                                            font.pixelSize: 11
                                            color: theme.okText
                                            elide: Label.ElideLeft
                                            width: parent.width - 16
                                            horizontalAlignment: Text.AlignHCenter
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
                        color: theme.fg
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
