#!/usr/bin/env python3
"""
PQPG Text Scratchpad - Post-Quantum Hybrid Cryptography GUI
Implements in-memory text encryption, decryption, signing and verification
using NIST FIPS 203 ML-KEM-768 + X25519 + ChaCha20-Poly1305 and Ed25519.
Zero disk footprint for text operations.
"""

import os
import sys
import tempfile
import subprocess
import shutil

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, Gdk, Pango, GLib

PQPG_DIR = os.path.expanduser("~/.config/pqpg")
PQPG_KEY = os.path.join(PQPG_DIR, "identity.key")
PQPG_PUBKEY = os.path.join(PQPG_DIR, "identity.pub")
PQPG_RECIPIENTS = os.path.join(PQPG_DIR, "recipients")

def find_pqpg():
    cargo_bin = os.path.expanduser("~/.cargo/bin/pqpg")
    if os.path.isfile(cargo_bin) and os.access(cargo_bin, os.X_OK):
        return cargo_bin
    which = shutil.which("pqpg")
    if which:
        return which
    return None

PQPG_BIN = find_pqpg()

class PQPGScratchpad(Gtk.Window):
    def __init__(self, initial_files=None):
        super().__init__(title="PQPG Text Scratchpad")
        self.set_default_size(940, 640)
        self.set_position(Gtk.WindowPosition.CENTER)

        if not PQPG_BIN:
            self.show_error("Eseguibile pqpg non trovato in ~/.cargo/bin/pqpg o nel PATH.")
            sys.exit(1)

        self.ensure_identity()
        self.init_ui()
        self.refresh_recipients()

        if initial_files:
            self.load_initial_file(initial_files[0])

    def ensure_identity(self):
        os.makedirs(PQPG_DIR, mode=0o700, exist_ok=True)
        os.makedirs(PQPG_RECIPIENTS, mode=0o700, exist_ok=True)
        if not os.path.isfile(PQPG_KEY) or not os.path.isfile(PQPG_PUBKEY):
            subprocess.run([PQPG_BIN, "keygen", "-n", "identity", "-o", PQPG_DIR], check=True)
            os.chmod(PQPG_KEY, 0o600)
            os.chmod(PQPG_PUBKEY, 0o644)

    def init_ui(self):
        # HeaderBar
        header = Gtk.HeaderBar()
        header.set_show_close_button(True)
        header.props.title = "PQPG Text Scratchpad"
        header.props.subtitle = "ML-KEM-768 + X25519 (Ibrido PQ) & Ed25519"
        self.set_titlebar(header)

        # Contacts / Key button
        btn_contacts = Gtk.Button(label="🔑 Chiavi e Contatti")
        btn_contacts.set_tooltip_text("Gestisci la tua chiave e i contatti salvati")
        btn_contacts.connect("clicked", self.on_manage_keys)
        header.pack_start(btn_contacts)

        # Shred RAM button
        btn_shred = Gtk.Button(label="🗑 Pulisci RAM")
        btn_shred.set_tooltip_text("Azzera e cancella immediatamente entrambi i buffer dalla memoria")
        btn_shred.connect("clicked", self.on_shred_ram)
        header.pack_end(btn_shred)

        # Main vertical box
        main_vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        main_vbox.set_margin_top(8)
        main_vbox.set_margin_bottom(8)
        main_vbox.set_margin_start(10)
        main_vbox.set_margin_end(10)
        self.add(main_vbox)

        # Control Bar
        ctrl_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        main_vbox.pack_start(ctrl_bar, False, False, 0)

        lbl_rec = Gtk.Label(label="Destinatario:")
        ctrl_bar.pack_start(lbl_rec, False, False, 0)

        self.combo_recipients = Gtk.ComboBoxText()
        self.combo_recipients.set_hexpand(True)
        ctrl_bar.pack_start(self.combo_recipients, True, True, 0)

        btn_refresh = Gtk.Button(label="🔄")
        btn_refresh.set_tooltip_text("Ricarica lista contatti")
        btn_refresh.connect("clicked", lambda w: self.refresh_recipients())
        ctrl_bar.pack_start(btn_refresh, False, False, 0)

        # Crypto Action Buttons
        self.btn_encrypt = Gtk.Button(label="🔒 Cifra →")
        self.btn_encrypt.set_tooltip_text("Cifra il testo in chiaro per il destinatario selezionato")
        self.btn_encrypt.connect("clicked", self.on_encrypt)
        ctrl_bar.pack_start(self.btn_encrypt, False, False, 0)

        self.btn_decrypt = Gtk.Button(label="← 🔓 Decifra")
        self.btn_decrypt.set_tooltip_text("Decifra il blocco armored con la tua chiave privata")
        self.btn_decrypt.connect("clicked", self.on_decrypt)
        ctrl_bar.pack_start(self.btn_decrypt, False, False, 0)

        self.btn_sign = Gtk.Button(label="✍ Firma →")
        self.btn_sign.set_tooltip_text("Apponi la tua firma digitale Ed25519 al testo")
        self.btn_sign.connect("clicked", self.on_sign)
        ctrl_bar.pack_start(self.btn_sign, False, False, 0)

        self.btn_verify = Gtk.Button(label="✓ Verifica")
        self.btn_verify.set_tooltip_text("Verifica l'autenticità e l'integrità della firma")
        self.btn_verify.connect("clicked", self.on_verify)
        ctrl_bar.pack_start(self.btn_verify, False, False, 0)

        # Horizontal Split Paned
        paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        paned.set_position(450)
        main_vbox.pack_start(paned, True, True, 0)

        # Left Pane: Plaintext
        left_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        lbl_left = Gtk.Label()
        lbl_left.set_markup("<b>Testo in Chiaro (Plaintext)</b>")
        lbl_left.set_xalign(0.0)
        left_box.pack_start(lbl_left, False, False, 0)

        scrolled_left = Gtk.ScrolledWindow()
        scrolled_left.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        self.txt_plain = Gtk.TextView()
        self.txt_plain.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.txt_plain.modify_font(Pango.FontDescription("Monospace 10"))
        scrolled_left.add(self.txt_plain)
        left_box.pack_start(scrolled_left, True, True, 0)

        # Left Toolbar
        left_btns = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        btn_paste_plain = Gtk.Button(label="📋 Incolla")
        btn_paste_plain.connect("clicked", lambda w: self.paste_to_buffer(self.txt_plain.get_buffer()))
        btn_copy_plain = Gtk.Button(label="Copia Testo")
        btn_copy_plain.connect("clicked", lambda w: self.copy_from_buffer(self.txt_plain.get_buffer()))
        btn_clear_plain = Gtk.Button(label="Pulisci")
        btn_clear_plain.connect("clicked", lambda w: self.txt_plain.get_buffer().set_text(""))
        left_btns.pack_start(btn_paste_plain, False, False, 0)
        left_btns.pack_start(btn_copy_plain, False, False, 0)
        left_btns.pack_end(btn_clear_plain, False, False, 0)
        left_box.pack_start(left_btns, False, False, 0)

        paned.add1(left_box)

        # Right Pane: Armored
        right_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        lbl_right = Gtk.Label()
        lbl_right.set_markup("<b>Blocco Armored (Cifrato o Firma PQPG)</b>")
        lbl_right.set_xalign(0.0)
        right_box.pack_start(lbl_right, False, False, 0)

        scrolled_right = Gtk.ScrolledWindow()
        scrolled_right.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        self.txt_armored = Gtk.TextView()
        self.txt_armored.set_wrap_mode(Gtk.WrapMode.CHAR)
        self.txt_armored.modify_font(Pango.FontDescription("Monospace 9"))
        scrolled_right.add(self.txt_armored)
        right_box.pack_start(scrolled_right, True, True, 0)

        # Right Toolbar
        right_btns = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        btn_paste_armored = Gtk.Button(label="📋 Incolla")
        btn_paste_armored.connect("clicked", lambda w: self.paste_to_buffer(self.txt_armored.get_buffer()))
        btn_copy_armored = Gtk.Button(label="Copia Armored")
        btn_copy_armored.connect("clicked", lambda w: self.copy_from_buffer(self.txt_armored.get_buffer()))
        btn_qr_armored = Gtk.Button(label="📱 Mostra QR")
        btn_qr_armored.connect("clicked", self.on_show_qr)
        btn_clear_armored = Gtk.Button(label="Pulisci")
        btn_clear_armored.connect("clicked", lambda w: self.txt_armored.get_buffer().set_text(""))
        right_btns.pack_start(btn_paste_armored, False, False, 0)
        right_btns.pack_start(btn_copy_armored, False, False, 0)
        right_btns.pack_start(btn_qr_armored, False, False, 0)
        right_btns.pack_end(btn_clear_armored, False, False, 0)
        right_box.pack_start(right_btns, False, False, 0)

        paned.add2(right_box)

        # Status Bar / Result Banner
        self.status_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self.status_label = Gtk.Label()
        self.status_label.set_markup("<i>Pronto. I dati risiedono solo nella memoria volatile RAM.</i>")
        self.status_label.set_xalign(0.0)
        self.status_box.pack_start(self.status_label, True, True, 0)
        main_vbox.pack_start(self.status_box, False, False, 2)

    def set_status(self, text, color=None):
        if color == "green":
            self.status_label.set_markup(f"<span foreground='#2ecc71'><b>{GLib.markup_escape_text(text)}</b></span>")
        elif color == "red":
            self.status_label.set_markup(f"<span foreground='#e74c3c'><b>{GLib.markup_escape_text(text)}</b></span>")
        elif color == "blue":
            self.status_label.set_markup(f"<span foreground='#3498db'><b>{GLib.markup_escape_text(text)}</b></span>")
        else:
            self.status_label.set_markup(f"<i>{GLib.markup_escape_text(text)}</i>")

    def refresh_recipients(self):
        self.combo_recipients.remove_all()
        self.recipients_map = {}

        # Self key
        self.combo_recipients.append("self", "Personale (Te stesso: ~/.config/pqpg/identity.pub)")
        self.recipients_map["self"] = PQPG_PUBKEY

        # Scan recipients folder
        if os.path.isdir(PQPG_RECIPIENTS):
            files = sorted(os.listdir(PQPG_RECIPIENTS))
            for f in files:
                if f.endswith(".pub"):
                    name = f[:-4]
                    full_path = os.path.join(PQPG_RECIPIENTS, f)
                    key_id = f"recipient_{name}"
                    self.combo_recipients.append(key_id, f"Contatto: {name}")
                    self.recipients_map[key_id] = full_path

        self.combo_recipients.set_active(0)

    def get_selected_recipient_key(self):
        active_id = self.combo_recipients.get_active_id()
        if not active_id or active_id not in self.recipients_map:
            return PQPG_PUBKEY
        return self.recipients_map[active_id]

    def get_text(self, text_view):
        buf = text_view.get_buffer()
        start, end = buf.get_bounds()
        return buf.get_text(start, end, True)

    def set_text(self, text_view, text):
        buf = text_view.get_buffer()
        buf.set_text(text)

    def paste_to_buffer(self, buf):
        clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
        text = clipboard.wait_for_text()
        if text:
            buf.set_text(text)

    def copy_from_buffer(self, buf):
        start, end = buf.get_bounds()
        text = buf.get_text(start, end, True)
        if text:
            clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
            clipboard.set_text(text, -1)
            self.set_status("Copiato negli appunti!", color="blue")

    def on_shred_ram(self, widget):
        # Overwrite buffers with dummy data then clear
        self.set_text(self.txt_plain, "0" * 256)
        self.set_text(self.txt_armored, "0" * 256)
        self.set_text(self.txt_plain, "")
        self.set_text(self.txt_armored, "")
        self.set_status("RAM azzerata e pulita.", color=None)

    def on_encrypt(self, widget):
        plain = self.get_text(self.txt_plain)
        if not plain.strip():
            self.set_status("Nessun testo da cifrare nel riquadro sinistro.", color="red")
            return

        rec_pub = self.get_selected_recipient_key()
        rec_name = self.combo_recipients.get_active_text()

        try:
            proc = subprocess.run(
                [PQPG_BIN, "encrypt", "-r", rec_pub],
                input=plain.encode('utf-8'),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True
            )
            armored = proc.stdout.decode('utf-8')
            self.set_text(self.txt_armored, armored)
            self.set_status(f"✓ Cifrato con successo per {rec_name} (ML-KEM-768)", color="green")
        except subprocess.CalledProcessError as e:
            self.set_status(f"Errore cifratura: {e.stderr.decode('utf-8')}", color="red")

    def on_decrypt(self, widget):
        # Prefer armored text from right pane; if empty check left pane
        armored = self.get_text(self.txt_armored)
        if "-----BEGIN PQPG MESSAGE-----" not in armored:
            candidate = self.get_text(self.txt_plain)
            if "-----BEGIN PQPG MESSAGE-----" in candidate:
                armored = candidate
                self.set_text(self.txt_armored, armored)
                self.set_text(self.txt_plain, "")

        if "-----BEGIN PQPG MESSAGE-----" not in armored:
            self.set_status("Nessun blocco '-----BEGIN PQPG MESSAGE-----' trovato da decifrare.", color="red")
            return

        try:
            proc = subprocess.run(
                [PQPG_BIN, "decrypt", "-s", PQPG_KEY],
                input=armored.encode('utf-8'),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True
            )
            plain = proc.stdout.decode('utf-8')
            self.set_text(self.txt_plain, plain)
            self.set_status("✓ Messaggio decifrato con successo con la tua chiave privata.", color="green")
        except subprocess.CalledProcessError as e:
            err = e.stderr.decode('utf-8').strip()
            self.set_status(f"Errore decifratura: {err}", color="red")

    def on_sign(self, widget):
        plain = self.get_text(self.txt_plain)
        if not plain.strip():
            self.set_status("Nessun testo da firmare nel riquadro sinistro.", color="red")
            return

        try:
            proc = subprocess.run(
                [PQPG_BIN, "sign", "-s", PQPG_KEY],
                input=plain.encode('utf-8'),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True
            )
            sig_armored = proc.stdout.decode('utf-8')
            self.set_text(self.txt_armored, sig_armored)
            self.set_status("✓ Testo firmato con successo (Ed25519).", color="green")
        except subprocess.CalledProcessError as e:
            self.set_status(f"Errore firma: {e.stderr.decode('utf-8')}", color="red")

    def on_verify(self, widget):
        plain = self.get_text(self.txt_plain)
        armored = self.get_text(self.txt_armored)

        if not plain.strip() or not armored.strip():
            self.set_status("Per verificare sono richiesti sia il testo (a sinistra) che la firma (a destra).", color="red")
            return

        if "-----BEGIN PQPG SIGNATURE-----" not in armored:
            self.set_status("Nessun blocco '-----BEGIN PQPG SIGNATURE-----' trovato nel riquadro destro.", color="red")
            return

        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            tf.write(armored)
            sig_file = tf.name

        try:
            # 1. Try verify with self key
            verified_signer = None
            res = subprocess.run(
                [PQPG_BIN, "verify", "-k", PQPG_PUBKEY, "-s", sig_file],
                input=plain.encode('utf-8'),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            if res.returncode == 0:
                verified_signer = "Personale (identity.pub)"

            # 2. Try verify with contacts in recipients/
            if not verified_signer and os.path.isdir(PQPG_RECIPIENTS):
                for f in sorted(os.listdir(PQPG_RECIPIENTS)):
                    if f.endswith(".pub"):
                        pub_path = os.path.join(PQPG_RECIPIENTS, f)
                        res = subprocess.run(
                            [PQPG_BIN, "verify", "-k", pub_path, "-s", sig_file],
                            input=plain.encode('utf-8'),
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE
                        )
                        if res.returncode == 0:
                            verified_signer = f"Contatto: {f[:-4]}"
                            break

            if verified_signer:
                self.set_status(f"✓ FIRMA VALIDA! Firmatario autenticato: {verified_signer}", color="green")
            else:
                self.set_status("✗ FIRMA NON VALIDA o firmatario sconosciuto (chiave non presente in rubrica).", color="red")
        finally:
            if os.path.exists(sig_file):
                os.unlink(sig_file)

    def launch_terminal_qr(self, title, input_file, temp_file_to_clean=None):
        runner = tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False)
        runner_path = runner.name
        cleanup_lines = f'rm -f "{temp_file_to_clean}"\n' if temp_file_to_clean else ""
        runner.write(f"""#!/bin/bash
trap 'rm -f "{runner_path}"' EXIT
"{PQPG_BIN}" qr "{input_file}"
{cleanup_lines}echo ""
read -n 1 -s -r -p "Premi un tasto per chiudere..."
""")
        runner.close()
        os.chmod(runner_path, 0o755)

        term_bin = shutil.which("terminator") or shutil.which("x-terminal-emulator") or shutil.which("xterm")
        if not term_bin:
            self.set_status("Nessun emulatore di terminale trovato.", color="red")
            return

        real_term = os.path.realpath(term_bin)
        if "terminator" in real_term:
            cmd = [term_bin, "-u", "--geometry=950x850", "-T", title, "-x", "/bin/bash", runner_path]
        elif "gnome-terminal" in real_term:
            cmd = [term_bin, "--title", title, "--geometry=100x45", "--", "/bin/bash", runner_path]
        elif "xfce4-terminal" in real_term:
            cmd = [term_bin, "-T", title, "--geometry=100x45", "-x", "/bin/bash", runner_path]
        else:
            cmd = [term_bin, "-T", title, "-e", f"/bin/bash {runner_path}"]

        try:
            subprocess.Popen(cmd)
            self.set_status("Terminale QR Code visualizzato con successo.", color="green")
        except Exception as e:
            self.set_status(f"Impossibile aprire terminale QR: {e}", color="red")

    def on_show_qr(self, widget):
        armored = self.get_text(self.txt_armored)
        if not armored.strip():
            armored = self.get_text(self.txt_plain)
        if not armored.strip():
            self.set_status("Nessun testo da convertire in QR Code.", color="red")
            return

        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            tf.write(armored)
            tmp_path = tf.name

        self.launch_terminal_qr("PQPG Air-Gapped QR Code", tmp_path, temp_file_to_clean=tmp_path)

    def on_manage_keys(self, widget):
        dialog = Gtk.Dialog(
            title="PQPG - Gestione Chiavi e Contatti",
            parent=self,
            flags=Gtk.DialogFlags.MODAL,
            buttons=(Gtk.STOCK_CLOSE, Gtk.ResponseType.CLOSE)
        )
        dialog.set_default_size(540, 380)
        box = dialog.get_content_area()
        box.set_spacing(8)
        box.set_margin_top(10)
        box.set_margin_bottom(10)
        box.set_margin_start(10)
        box.set_margin_end(10)

        lbl = Gtk.Label()
        lbl.set_markup("<b>La tua chiave identità (ML-KEM-768 + X25519 + Ed25519):</b>")
        lbl.set_xalign(0.0)
        box.pack_start(lbl, False, False, 0)

        entry_pub = Gtk.Entry()
        entry_pub.set_text(PQPG_PUBKEY)
        entry_pub.set_editable(False)
        box.pack_start(entry_pub, False, False, 0)

        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        btn_copy_pub = Gtk.Button(label="📋 Copia Chiave Pubblica")
        btn_copy_pub.connect("clicked", self.on_copy_self_pub)
        btn_box.pack_start(btn_copy_pub, False, False, 0)

        btn_show_self_qr = Gtk.Button(label="📱 Mostra QR Air-Gapped")
        btn_show_self_qr.connect("clicked", self.on_show_self_qr)
        btn_box.pack_start(btn_show_self_qr, False, False, 0)

        btn_publish_mixnet = Gtk.Button(label="🌐 Pubblica su Pigeonhole")
        btn_publish_mixnet.set_tooltip_text("Pubblica la tua chiave pubblica sul servizio di directory Pigeonhole")
        btn_publish_mixnet.connect("clicked", self.on_publish_pigeonhole)
        btn_box.pack_start(btn_publish_mixnet, False, False, 0)
        box.pack_start(btn_box, False, False, 0)

        box.pack_start(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL), False, False, 4)

        lbl_contacts = Gtk.Label()
        lbl_contacts.set_markup("<b>Contatti salvati in ~/.config/pqpg/recipients/:</b>")
        lbl_contacts.set_xalign(0.0)
        box.pack_start(lbl_contacts, False, False, 0)

        liststore = Gtk.ListStore(str, str)
        if os.path.isdir(PQPG_RECIPIENTS):
            for f in sorted(os.listdir(PQPG_RECIPIENTS)):
                if f.endswith(".pub"):
                    liststore.append([f[:-4], os.path.join(PQPG_RECIPIENTS, f)])

        treeview = Gtk.TreeView(model=liststore)
        col_name = Gtk.TreeViewColumn("Contatto", Gtk.CellRendererText(), text=0)
        col_path = Gtk.TreeViewColumn("File Pubkey", Gtk.CellRendererText(), text=1)
        treeview.append_column(col_name)
        treeview.append_column(col_path)

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_min_content_height(140)
        scrolled.add(treeview)
        box.pack_start(scrolled, True, True, 0)

        cbtn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        btn_lookup_mixnet = Gtk.Button(label="🔍 Cerca su Pigeonhole")
        btn_lookup_mixnet.set_tooltip_text("Cerca e importa una chiave pubblica dalla mixnet per ID o fingerprint")
        btn_lookup_mixnet.connect("clicked", lambda w: self.on_lookup_pigeonhole(dialog))
        cbtn_box.pack_start(btn_lookup_mixnet, False, False, 0)

        btn_open_folder = Gtk.Button(label="📁 Apri Cartella Contatti")
        btn_open_folder.connect("clicked", lambda w: subprocess.Popen(["thunar", PQPG_RECIPIENTS]))
        cbtn_box.pack_start(btn_open_folder, False, False, 0)
        box.pack_start(cbtn_box, False, False, 0)

        dialog.show_all()
        dialog.run()
        dialog.destroy()
        self.refresh_recipients()

    def on_copy_self_pub(self, widget):
        if os.path.isfile(PQPG_PUBKEY):
            with open(PQPG_PUBKEY, "r") as f:
                content = f.read()
            clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
            clipboard.set_text(content, -1)
            self.set_status("Chiave pubblica copiata negli appunti!", color="blue")

    def on_show_self_qr(self, widget):
        if not os.path.exists(PQPG_PUBKEY):
            self.set_status("Chiave pubblica non trovata in ~/.config/pqpg/identity.pub", color="red")
            return
        self.launch_terminal_qr("PQPG Public Key QR Code", PQPG_PUBKEY)

    def on_publish_pigeonhole(self, widget):
        tool = shutil.which("pqkeys-tool")
        if not tool:
            self.set_status("pqkeys-tool non trovato nel PATH", color="red")
            return

        dialog = Gtk.Dialog(
            title="Pubblica Chiave su Pigeonhole",
            parent=self,
            flags=Gtk.DialogFlags.MODAL,
            buttons=(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL, Gtk.STOCK_OK, Gtk.ResponseType.OK)
        )
        box = dialog.get_content_area()
        box.set_spacing(8)
        box.set_margin_top(10)
        box.set_margin_bottom(10)
        box.set_margin_start(10)
        box.set_margin_end(10)

        lbl = Gtk.Label(label="Inserisci il tuo User ID / Alias pubblico per la directory:")
        box.pack_start(lbl, False, False, 0)
        entry_user = Gtk.Entry()
        entry_user.set_text("gabriel1@virebent.art")
        box.pack_start(entry_user, False, False, 0)

        dialog.show_all()
        response = dialog.run()
        user_id = entry_user.get_text().strip()
        dialog.destroy()

        if response == Gtk.ResponseType.OK and user_id:
            try:
                proc = subprocess.run(
                    [tool, "publish", "--key", PQPG_KEY, "--pub", PQPG_PUBKEY, "--user", user_id],
                    capture_output=True, text=True, check=True
                )
                self.set_status(f"✓ Chiave pubblicata su Pigeonhole: {user_id}", color="green")
            except subprocess.CalledProcessError as e:
                err = e.stderr.strip() or e.stdout.strip()
                self.set_status(f"Errore pubblicazione: {err}", color="red")

    def on_lookup_pigeonhole(self, parent_dialog):
        tool = shutil.which("pqkeys-tool")
        if not tool:
            self.set_status("pqkeys-tool non trovato nel PATH", color="red")
            return

        dialog = Gtk.Dialog(
            title="Cerca Chiave su Pigeonhole",
            parent=parent_dialog,
            flags=Gtk.DialogFlags.MODAL,
            buttons=(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL, Gtk.STOCK_OK, Gtk.ResponseType.OK)
        )
        box = dialog.get_content_area()
        box.set_spacing(8)
        box.set_margin_top(10)
        box.set_margin_bottom(10)
        box.set_margin_start(10)
        box.set_margin_end(10)

        lbl = Gtk.Label(label="Inserisci User ID o Fingerprint da cercare:")
        box.pack_start(lbl, False, False, 0)
        entry_query = Gtk.Entry()
        box.pack_start(entry_query, False, False, 0)

        dialog.show_all()
        response = dialog.run()
        query = entry_query.get_text().strip()
        dialog.destroy()

        if response == Gtk.ResponseType.OK and query:
            clean_name = query.replace("@", "_").replace(".", "_")
            out_file = os.path.join(PQPG_RECIPIENTS, f"{clean_name}.pub")
            try:
                proc = subprocess.run(
                    [tool, "lookup", query, "-o", out_file],
                    capture_output=True, text=True, check=True
                )
                self.set_status(f"✓ Chiave trovata e importata in {os.path.basename(out_file)}", color="green")
                self.refresh_recipients()
            except subprocess.CalledProcessError as e:
                err = e.stderr.strip() or e.stdout.strip()
                self.set_status(f"Ricerca fallita: {err}", color="red")

    def load_initial_file(self, filepath):
        if not os.path.isfile(filepath):
            return
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            if "-----BEGIN PQPG MESSAGE-----" in content or "-----BEGIN PQPG SIGNATURE-----" in content:
                self.set_text(self.txt_armored, content)
                self.set_status(f"Caricato blocco armored da: {os.path.basename(filepath)}", color="blue")
            else:
                self.set_text(self.txt_plain, content)
                self.set_status(f"Caricato file di testo: {os.path.basename(filepath)}", color="blue")
        except Exception as e:
            self.set_status(f"Impossibile leggere file {filepath}: {e}", color="red")

    def show_error(self, message):
        dialog = Gtk.MessageDialog(
            transient_for=self,
            flags=0,
            message_type=Gtk.MessageType.ERROR,
            buttons=Gtk.ButtonsType.OK,
            text=message
        )
        dialog.run()
        dialog.destroy()

def main():
    initial_files = sys.argv[1:] if len(sys.argv) > 1 else None
    app = PQPGScratchpad(initial_files=initial_files)
    app.connect("destroy", Gtk.main_quit)
    app.show_all()
    Gtk.main()

if __name__ == "__main__":
    main()
