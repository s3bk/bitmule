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

    /// Bytes as a person reads them: "1.4 GB", "812 kB".
    function humanSize(n) {
        var units = ["B", "kB", "MB", "GB", "TB"]
        var v = Number(n) || 0
        var i = 0
        while (v >= 1000 && i < units.length - 1) { v /= 1000; i++ }
        return (i === 0 ? Math.round(v) : (v < 10 ? v.toFixed(1) : Math.round(v))) + " " + units[i]
    }

    UploaderApi {
        id: api
        Component.onCompleted: api.init_from_qml()
    }

    AccountApi {
        id: account
        Component.onCompleted: account.init_from_qml()
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 10
        spacing: 10

        // ---------- Tab bar ----------
        TabBar {
            id: bar
            Layout.fillWidth: true
            // `--account` opens on the account tab: for screenshots, and for
            // the one case where the app starts because an account needs
            // attention.
            currentIndex: Qt.application.arguments.indexOf("--account") >= 0 ? 3 : 0
            TabButton {
                id: tabSend
                text: "Send"
                // Basic's TabButton fills an unchecked tab with `palette.dark`
                // and writes its label in `brightText`; from the window palette
                // that is a near-black slab with white text on a light theme.
                // The tab bar gets its own surfaces instead: checked = card,
                // unchecked = muted, labels from the text roles.
                palette.dark: theme.surfaceMuted
                palette.mid: theme.surfaceMuted
                palette.window: theme.surface
                palette.brightText: theme.fgMuted
                palette.windowText: theme.fg
            }
            TabButton {
                id: tabActive
                text: "Active"
                palette.dark: theme.surfaceMuted
                palette.mid: theme.surfaceMuted
                palette.window: theme.surface
                palette.brightText: theme.fgMuted
                palette.windowText: theme.fg
            }
            TabButton {
                id: tabRecv
                text: "Receive"
                palette.dark: theme.surfaceMuted
                palette.mid: theme.surfaceMuted
                palette.window: theme.surface
                palette.brightText: theme.fgMuted
                palette.windowText: theme.fg
            }
            TabButton {
                id: tabAccount
                text: "Account"
                palette.dark: theme.surfaceMuted
                palette.mid: theme.surfaceMuted
                palette.window: theme.surface
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
                    // Dropping while a share is preparing is how a second one
                    // starts; the list is never locked by a running send.
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
                                width: parent.width
                                font.pixelSize: 12
                                // One row is one path; the cross takes it out
                                // of the share without emptying the list.
                                contentItem: RowLayout {
                                    spacing: 4
                                    Label {
                                        text: modelData
                                        elide: Text.ElideMiddle
                                        font.pixelSize: 12
                                        Layout.fillWidth: true
                                    }
                                    ToolButton {
                                        text: "\u2715"
                                        font.pixelSize: 11
                                        onClicked: api.remove_file(index)
                                        ToolTip.visible: hovered
                                        ToolTip.text: "Remove from this share"
                                        ToolTip.delay: 400
                                    }
                                }
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

                RowLayout {
                    spacing: 8
                    Button {
                        id: shareButton
                        text: "Share"
                        Layout.fillWidth: true
                        // A share that is still running is not a reason to
                        // refuse another one: each gets its own session.
                        enabled: api.file_list.length > 0
                        onClicked: api.trigger_share()
                    }
                    Button {
                        text: "Clear"
                        enabled: api.file_list.length > 0
                        onClicked: api.clear_files()
                    }
                }

                Label {
                    text: "Preparing…"
                    visible: api.is_busy
                    Layout.alignment: Qt.AlignHCenter
                    color: theme.fgMuted
                    font.pixelSize: 12
                }

                Label {
                    text: api.share_error
                    visible: api.share_error.length > 0
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                    color: theme.danger
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

            // ---------- Active tab ----------
            //
            // Everything this window is sending, oldest first — the sends that
            // used to be hidden behind the one Send tab, which could only show
            // the newest link and stopped being useful the moment a second
            // share was started. A row stays after its transfer ends so the
            // link can still be copied; "✕" forgets it.
            ColumnLayout {
                spacing: 10

                GroupBox {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    title: api.sends.length > 0
                        ? "Sending (" + api.sends.length + ")"
                        : "Nothing is being sent"

                    ListView {
                        id: sendsView
                        anchors.fill: parent
                        model: api.sends
                        spacing: 6
                        clip: true
                        delegate: Rectangle {
                            width: ListView.view.width
                            height: sendCol.implicitHeight + 12
                            color: theme.surface
                            border.color: theme.border
                            border.width: 1
                            radius: 6

                            property var send: JSON.parse(modelData || "{}")

                            ColumnLayout {
                                id: sendCol
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
                                        text: send.name || "(preparing…)"
                                    }
                                    Label {
                                        font.pixelSize: 11
                                        color: send.status === "error" || send.status === "stopped"
                                            ? theme.danger
                                            : theme.fgMuted
                                        text: send.status === "live"
                                            ? (send.peers > 1 ? send.peers + " receivers" : "shared")
                                            : send.status === "preparing" ? "preparing"
                                            : send.status === "done" ? "done"
                                            : send.status === "stopped" ? "stopped" : "failed"
                                    }
                                    Button {
                                        // One x, whose meaning follows the row: while
                                        // the share is still going it stops it, and
                                        // once it is over it forgets the row. Two x's
                                        // side by side said the same thing twice.
                                        text: "×"
                                        ToolTip.visible: hovered
                                        ToolTip.text: send.status === "preparing" || send.status === "live"
                                            ? "Stop this transfer"
                                            : "Forget this entry"
                                        ToolTip.delay: 400
                                        onClicked: send.status === "preparing" || send.status === "live"
                                            ? api.stop_send("" + send.id)
                                            : api.drop_send("" + send.id)
                                    }
                                }

                                Label {
                                    Layout.fillWidth: true
                                    font.pixelSize: 11
                                    color: theme.fgMuted
                                    visible: send.status === "preparing"
                                    text: (send.phase || "working") + "…"
                                }
                                ProgressBar {
                                    Layout.fillWidth: true
                                    from: 0; to: 1
                                    value: send.progress || 0
                                    visible: send.status === "live" || send.status === "done"
                                }
                                Label {
                                    Layout.fillWidth: true
                                    font.pixelSize: 11
                                    color: theme.fgMuted
                                    visible: send.status === "live" || send.status === "done"
                                    text: Math.round((send.progress || 0) * 100) + "% of "
                                        + window.humanSize(send.size || 0)
                                }
                                Label {
                                    Layout.fillWidth: true
                                    font.pixelSize: 11
                                    wrapMode: Text.Wrap
                                    color: theme.danger
                                    visible: send.status === "error" && (send.error || "").length > 0
                                    text: send.error || ""
                                }
                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: 6
                                    visible: (send.url || "").length > 0
                                    TextField {
                                        Layout.fillWidth: true
                                        text: send.url || ""
                                        readOnly: true
                                        selectByMouse: true
                                        font.pixelSize: 11
                                    }
                                    Button {
                                        text: "Copy"
                                        onClicked: api.copy_text(send.url || "")
                                    }
                                }
                            }
                        }
                    }
                }

                Label {
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                    color: theme.fgFaint
                    font.pixelSize: 11
                    text: "A link keeps working while this window is open. Starting "
                        + "another share does not stop the ones already running."
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
                        placeholderText: "paste bitmule URL (https://mul.li#…)"
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
            // ---------- Account tab ----------
            //
            // The same account the browser has: one record on this device,
            // sealed under the password, made and opened by the same code
            // (bitmule-account) as bitmule.net/app's vault.js. Nothing here
            // is sent anywhere except the one activation call, which spends
            // the operator's one-time token so the account may mint storage.
            // The password is not the person's to remember: it is made by the
            // app or typed once, and then the key it unlocks is kept in the
            // desktop's keyring, so a lock or a restart opens without a
            // prompt. Without a keyring the password is asked for, and
            // nothing else changes.
            ColumnLayout {
                spacing: 10

                Label {
                    Layout.fillWidth: true
                    wrapMode: Label.WordWrap
                    font.pixelSize: 12
                    color: theme.fgMuted
                    text: "An account is a key pair on this device. It is what may "
                        + "create a share or an invite on the server; sending and "
                        + "receiving a link never needs it."
                }

                Label {
                    Layout.fillWidth: true
                    font.pixelSize: 13
                    color: theme.fg
                    text: {
                        if (account.state === "unlocked")
                            return account.label + "  ·  " + account.plan
                        if (account.state === "locked")
                            return account.label + "  ·  locked"
                        return "No account on this device"
                    }
                }

                // ---- create: nothing on disk yet ----
                GroupBox {
                    Layout.fillWidth: true
                    title: "Create"
                    visible: account.state === "none"
                    ColumnLayout {
                        anchors.fill: parent
                        spacing: 8
                        Label {
                            Layout.fillWidth: true
                            wrapMode: Label.WordWrap
                            font.pixelSize: 11
                            color: theme.fgFaint
                            text: "The key is made here; the server is not asked anything. "
                                + "You get a record you can back up, and the same password "
                                + "opens it at bitmule.net/app. Leave the password empty and "
                                + "one is made for you and kept in the desktop's keyring — "
                                + "nothing to remember."
                        }
                        TextField {
                            id: createLabel
                            Layout.fillWidth: true
                            placeholderText: "what to call it (e.g. \"laptop\")"
                            font.pixelSize: 12
                        }
                        TextField {
                            id: createPassword
                            Layout.fillWidth: true
                            placeholderText: "password (10+ characters, or empty for none)"
                            echoMode: TextInput.Password
                            font.pixelSize: 12
                        }
                        TextField {
                            id: createPassword2
                            Layout.fillWidth: true
                            placeholderText: "password again"
                            echoMode: TextInput.Password
                            font.pixelSize: 12
                        }
                        CheckBox {
                            id: createRemember
                            text: "Keep the key in the keyring (KWallet)"
                            checked: account.remember
                            font.pixelSize: 11
                            onToggled: account.set_remember(checked)
                        }
                        Button {
                            Layout.fillWidth: true
                            text: "Create account"
                            enabled: !account.busy && createLabel.text.length > 0
                                && createPassword.text === createPassword2.text
                            onClicked: {
                                if (account.create_account(createLabel.text, createPassword.text)) {
                                    createPassword.text = ""
                                    createPassword2.text = ""
                                }
                            }
                        }
                    }
                }

                // ---- the password the app made, shown once ----
                GroupBox {
                    Layout.fillWidth: true
                    title: "Write this down"
                    visible: account.recovery.length > 0
                    ColumnLayout {
                        anchors.fill: parent
                        spacing: 8
                        Label {
                            Layout.fillWidth: true
                            wrapMode: Label.WordWrap
                            font.pixelSize: 11
                            color: theme.fgFaint
                            text: "The app made this password and keeps the key in the keyring, "
                                + "so you never have to type it. It is the only way a copy "
                                + "of the record can be opened in a browser; this is the one "
                                + "time it is shown."
                        }
                        TextField {
                            Layout.fillWidth: true
                            readOnly: true
                            text: account.recovery
                            font.pixelSize: 12
                            font.family: "monospace"
                            selectByMouse: true
                        }
                    }
                }

                // ---- unlock: a record on disk, no key in memory ----
                GroupBox {
                    Layout.fillWidth: true
                    title: "Unlock"
                    visible: account.state === "locked"
                    ColumnLayout {
                        anchors.fill: parent
                        spacing: 8
                        Label {
                            Layout.fillWidth: true
                            wrapMode: Label.WordWrap
                            font.pixelSize: 11
                            color: theme.fgFaint
                            text: {
                                if (account.keyring === "checking")
                                    return "Asking the keyring for this account's key…"
                                if (account.keyring === "stored")
                                    return "Its key is in the keyring."
                                if (account.keyring === "unavailable")
                                    return "No keyring on this session (KWallet 6 or GNOME "
                                        + "Keyring), so the password is typed here."
                                return "The password you typed when this record was made."
                            }
                        }
                        TextField {
                            id: unlockPassword
                            Layout.fillWidth: true
                            placeholderText: "password"
                            echoMode: TextInput.Password
                            font.pixelSize: 12
                            onAccepted: unlockButton.clicked()
                        }
                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 6
                            Button {
                                id: unlockButton
                                Layout.fillWidth: true
                                text: "Unlock"
                                enabled: !account.busy && unlockPassword.text.length > 0
                                onClicked: {
                                    if (account.unlock(unlockPassword.text))
                                        unlockPassword.text = ""
                                }
                            }
                            Button {
                                Layout.fillWidth: true
                                text: "Use the keyring"
                                visible: account.keyring !== "unavailable"
                                    && account.keyring !== "nothing"
                                enabled: !account.busy && account.keyring !== "checking"
                                onClicked: account.unlock_from_keyring()
                            }
                        }
                    }
                }

                // ---- unlocked: the account, and activation ----
                GroupBox {
                    Layout.fillWidth: true
                    title: account.activated ? "This account" : "Activate"
                    visible: account.state === "unlocked"
                    ColumnLayout {
                        anchors.fill: parent
                        spacing: 8

                        Label {
                            Layout.fillWidth: true
                            font.pixelSize: 11
                            color: theme.fgFaint
                            text: account.activated
                                ? account.account_id
                                : "Not activated: this key may not mint storage yet."
                            elide: Label.ElideMiddle
                        }

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 6
                            TextField {
                                id: tokenField
                                Layout.fillWidth: true
                                visible: !account.activated
                                placeholderText: "one-time token (tk_…)"
                                font.pixelSize: 12
                            }
                            Button {
                                Layout.fillWidth: true
                                visible: !account.activated
                                text: "Activate"
                                enabled: !account.busy && tokenField.text.length > 0
                                onClicked: account.activate(tokenField.text)
                            }
                        }

                        Label {
                            Layout.fillWidth: true
                            visible: account.busy
                            font.pixelSize: 11
                            color: theme.fgMuted
                            text: "Talking to the server…"
                        }

                        CheckBox {
                            Layout.fillWidth: true
                            text: "Keep the key in the keyring"
                            checked: account.remember
                            font.pixelSize: 11
                            onToggled: account.set_remember(checked)
                        }

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 6
                            Button {
                                Layout.fillWidth: true
                                text: "Lock"
                                onClicked: account.lock()
                            }
                            Button {
                                Layout.fillWidth: true
                                text: "Forget this device"
                                onClicked: account.forget()
                            }
                        }
                    }
                }

                Label {
                    Layout.fillWidth: true
                    visible: account.error.length > 0
                    wrapMode: Label.WordWrap
                    font.pixelSize: 11
                    color: theme.danger
                    text: account.error
                }

                Item { Layout.fillHeight: true }
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

    // A video that is not AV1 yet is offered a conversion before it goes out.
    // The question is a card over the window rather than a dialog: it is one
    // decision with three answers, and it belongs to the Send tab that is
    // already in front of the person. `api.video_offer` is JSON from Rust
    // (`video_offer_for`); while a conversion runs the same card shows its
    // progress, then the share starts by itself.
    Rectangle {
        id: videoCard
        anchors.fill: parent
        z: 50
        // One answer to "is there anything to show", so no binding has to
        // reach into a possibly empty object.
        property var videoOffer: {
            if (api.video_offer.length === 0) return ({})
            try { return JSON.parse(api.video_offer) } catch (e) { return ({}) }
        }
        property bool hasOffer: api.video_offer.length > 0
        visible: hasOffer || api.converting.length > 0
        color: "#99000000"

        // clicks behind the card do nothing: the share is waiting for an answer
        MouseArea { anchors.fill: parent }

        Rectangle {
            id: videoPanel
            anchors.centerIn: parent
            width: Math.min(parent.width - 56, 420)
            height: videoBody.height + 32
            radius: 10
            color: theme.surface
            border.width: 1
            border.color: theme.borderStrong

            ColumnLayout {
                id: videoBody
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: parent.top
                anchors.margins: 16
                spacing: 10

                // ---- converting ----
                Label {
                    Layout.fillWidth: true
                    visible: api.converting.length > 0
                    text: api.converting
                    color: theme.fg
                    font.pixelSize: 14
                    wrapMode: Text.Wrap
                }
                ProgressBar {
                    Layout.fillWidth: true
                    visible: api.converting.length > 0
                    from: 0
                    to: 1
                    value: api.convert_progress
                }
                Label {
                    Layout.fillWidth: true
                    visible: api.converting.length > 0
                    text: "The link appears when the conversion is done. The original file stays as it is."
                    color: theme.fgMuted
                    font.pixelSize: 11
                    wrapMode: Text.Wrap
                }
                Button {
                    Layout.fillWidth: true
                    visible: api.converting.length > 0
                    text: "Don't wait — send it now"
                    onClicked: api.cancel_conversion()
                }

                // ---- the question ----
                Label {
                    Layout.fillWidth: true
                    visible: api.converting.length === 0
                    text: "Convert it first, or send it now?"
                    color: theme.fg
                    font.pixelSize: 15
                    font.bold: true
                }
                Label {
                    Layout.fillWidth: true
                    visible: api.converting.length === 0
                    text: (videoCard.videoOffer.name || "video") + " — "
                        + (videoCard.videoOffer.sizeText || "") + (videoCard.videoOffer.durationText ? ", " + videoCard.videoOffer.durationText : "")
                        + (videoCard.videoOffer.codec ? " (" + videoCard.videoOffer.codec + ")" : "")
                    color: theme.fgMuted
                    font.pixelSize: 12
                    wrapMode: Text.Wrap
                }
                Label {
                    Layout.fillWidth: true
                    visible: api.converting.length === 0
                    text: "Converting first means waiting: the file is re-encoded in full, so the link only appears when that is done — "
                        + "minutes for a clip, longer for a film. It is worth it when the other side is a browser and cannot play "
                        + (videoCard.videoOffer.codec || "this codec") + ". Sending it now starts the link at once and sends exactly these bytes."
                    color: theme.fgMuted
                    font.pixelSize: 11
                    wrapMode: Text.Wrap
                }
                Repeater {
                    model: api.converting.length === 0 ? videoCard.videoOffer.profiles || [] : []
                    delegate: Button {
                        Layout.fillWidth: true
                        text: "Convert first — " + modelData.label
                        onClicked: api.decide_video(modelData.key)
                    }
                }
                Button {
                    Layout.fillWidth: true
                    visible: api.converting.length === 0
                    text: "Send now, as it is"
                    onClicked: api.decide_video("as-is")
                }
            }
        }
    }
}
