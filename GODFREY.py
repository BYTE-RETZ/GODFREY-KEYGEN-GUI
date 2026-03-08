import math
import os
import sys

from argon2.exceptions import Argon2Error
from PySide6.QtCore import QEasingCurve, QPropertyAnimation, QTimer, Qt
from PySide6.QtGui import QFont, QFontMetrics
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QGraphicsOpacityEffect,
    QGridLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QListWidget,
    QListWidgetItem,
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from godfrey_core import (
    DecryptionError,
    StorageWriteError,
    build_storage_paths,
    encrypt_existing_passwords as core_encrypt_existing_passwords,
    generate_password_artifacts,
    read_password_store as core_read_password_store,
    save_master_password as core_save_master_password,
    verify_master_password as core_verify_master_password,
    write_password_store as core_write_password_store,
)

FONT_NAME = "Quantico"

IS_FROZEN = getattr(sys, "frozen", False)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

if IS_FROZEN:
    APP_DIR = os.path.dirname(os.path.abspath(sys.executable))
    BUNDLE_DIR = getattr(sys, "_MEIPASS", APP_DIR)
else:
    APP_DIR = SCRIPT_DIR
    BUNDLE_DIR = SCRIPT_DIR

PATHS = build_storage_paths(APP_DIR)
MASTER_KEY_FILE = PATHS.master_key_file
PASSWORD_STORE_FILE = PATHS.password_store_file
DRAGON_ART_FILE = os.path.join(APP_DIR, "dragon_ascii.txt")
RIGHT_DRAGON_ART_FILE = os.path.join(APP_DIR, "right_ascii.txt")
BUNDLED_DRAGON_ART_FILE = os.path.join(BUNDLE_DIR, "dragon_ascii.txt")
BUNDLED_RIGHT_DRAGON_ART_FILE = os.path.join(BUNDLE_DIR, "right_ascii.txt")


class GodfreyWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.master_password_cache = []
        self._typing_text = ""
        self._typing_index = 0
        self._intro_started = False
        self._intro_animations = []
        self._wave_position = -0.8
        self._dragon_lines = []
        self._right_dragon_lines = []

        self.setWindowTitle("GODFREY KEYGEN (PySide6)")
        self.setObjectName("appWindow")
        self._build_geometry()
        self._build_ui()
        self._apply_theme()

        self.typing_timer = QTimer(self)
        self.typing_timer.setInterval(35)
        self.typing_timer.timeout.connect(self._type_tick)

        self.hero_wave_timer = QTimer(self)
        self.hero_wave_timer.setInterval(60)
        self.hero_wave_timer.timeout.connect(self._update_hero_wave)

    def _build_geometry(self):
        screen = QApplication.primaryScreen()
        if screen is None:
            self.resize(1200, 800)
            self.setMinimumSize(800, 500)
            return

        rect = screen.availableGeometry()
        width = int(rect.width() * 0.72)
        height = int(rect.height() * 0.72)
        self.resize(width, height)
        self.setMinimumSize(int(rect.width() * 0.45), int(rect.height() * 0.45))

    def _build_ui(self):
        central = QWidget(self)
        central.setObjectName("rootCanvas")
        self.setCentralWidget(central)

        root_layout = QVBoxLayout()
        root_layout.setContentsMargins(24, 24, 24, 24)
        root_layout.setSpacing(14)
        central.setLayout(root_layout)

        self.hero_reserve = QWidget()
        self.hero_reserve.setObjectName("heroReserve")
        self.hero_reserve.setMinimumHeight(380)

        hero_layout = QHBoxLayout(self.hero_reserve)
        hero_layout.setContentsMargins(14, 14, 14, 14)
        hero_layout.setSpacing(28)

        self._dragon_lines = self._load_dragon_lines()
        self.dragon_label = QLabel("\n".join(self._dragon_lines))
        self.dragon_label.setObjectName("dragonAscii")
        self.dragon_label.setFont(QFont("Cascadia Mono", 5))
        self.dragon_label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)

        self._right_dragon_lines = self._load_right_dragon_lines()
        self.right_dragon_label = QLabel("\n".join(self._right_dragon_lines))
        self.right_dragon_label.setObjectName("dragonAscii")
        self.right_dragon_label.setFont(QFont("Cascadia Mono", 10))
        self.right_dragon_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        title_layout = QVBoxLayout()
        title_layout.setContentsMargins(0, 0, 0, 0)
        title_layout.setSpacing(6)

        self.hero_title_label = QLabel("GODFREY")
        self.hero_title_label.setObjectName("heroTitleLabel")
        self.hero_title_label.setFont(QFont(FONT_NAME, 120, QFont.Bold))
        self.hero_title_label.setAlignment(Qt.AlignCenter | Qt.AlignBottom)

        self.hero_tagline_label = QLabel("THE PASSWORD FORTRESS")
        self.hero_tagline_label.setObjectName("heroTaglineLabel")
        self.hero_tagline_label.setFont(QFont(FONT_NAME, 30, QFont.Bold))
        self.hero_tagline_label.setAlignment(Qt.AlignCenter | Qt.AlignTop)

        title_layout.addStretch(1)
        title_layout.addWidget(self.hero_title_label)
        title_layout.addWidget(self.hero_tagline_label)
        title_layout.addStretch(1)

        hero_layout.addWidget(self.dragon_label, 0, Qt.AlignLeft | Qt.AlignVCenter)
        hero_layout.addLayout(title_layout, 1)
        hero_layout.addWidget(self.right_dragon_label, 0, Qt.AlignRight | Qt.AlignVCenter)

        root_layout.addWidget(self.hero_reserve)

        self.panel = QWidget()
        self.panel.setObjectName("glassPanel")
        panel_layout = QVBoxLayout(self.panel)
        panel_layout.setContentsMargins(18, 16, 18, 16)
        panel_layout.setSpacing(10)

        form_layout = QGridLayout()
        form_layout.setVerticalSpacing(8)
        form_layout.setHorizontalSpacing(12)

        word_label = QLabel("WORD")
        word_label.setFont(QFont(FONT_NAME, 14))
        form_layout.addWidget(word_label, 0, 0)

        self.word_entry = QLineEdit()
        self.word_entry.setEchoMode(QLineEdit.Password)
        self.word_entry.setFont(QFont(FONT_NAME, 13))
        self.word_entry.setPlaceholderText("username")
        form_layout.addWidget(self.word_entry, 0, 1)

        self.show_word_check = QCheckBox("Show")
        self.show_word_check.toggled.connect(self._toggle_word_visibility)
        form_layout.addWidget(self.show_word_check, 0, 2)

        salt_label = QLabel("SALT")
        salt_label.setFont(QFont(FONT_NAME, 14))
        form_layout.addWidget(salt_label, 1, 0)

        self.salt_entry = QLineEdit()
        self.salt_entry.setEchoMode(QLineEdit.Password)
        self.salt_entry.setFont(QFont(FONT_NAME, 13))
        self.salt_entry.setPlaceholderText("a secretive word of minimum 8 characters")
        form_layout.addWidget(self.salt_entry, 1, 1)

        self.show_salt_check = QCheckBox("Show")
        self.show_salt_check.toggled.connect(self._toggle_salt_visibility)
        form_layout.addWidget(self.show_salt_check, 1, 2)

        settings_row = QHBoxLayout()
        settings_row.setSpacing(10)

        self.length_label = QLabel("LENGTH")
        self.length_label.setFont(QFont(FONT_NAME, 13))
        settings_row.addWidget(self.length_label)
        self.length_spin = QSpinBox()
        self.length_spin.setFont(QFont(FONT_NAME, 12))
        self.length_spin.setRange(4, 64)
        self.length_spin.setValue(16)
        settings_row.addWidget(self.length_spin)

        self.upper_check = QCheckBox("Uppercase")
        self.upper_check.setChecked(True)
        settings_row.addWidget(self.upper_check)

        self.lower_check = QCheckBox("Lowercase")
        self.lower_check.setChecked(True)
        settings_row.addWidget(self.lower_check)

        self.special_check = QCheckBox("Special")
        self.special_check.setChecked(True)
        settings_row.addWidget(self.special_check)

        self.numeric_pin_check = QCheckBox("Numeric Pin")
        self.numeric_pin_check.setChecked(True)
        settings_row.addWidget(self.numeric_pin_check)

        for checkbox in (self.upper_check, self.lower_check, self.special_check, self.numeric_pin_check):
            checkbox.setFont(QFont(FONT_NAME, 12))
            checkbox.toggled.connect(self._update_length_control_state)

        self._update_length_control_state()

        settings_row.addStretch(1)

        form_layout.addLayout(settings_row, 2, 0, 1, 3)

        form_layout.setColumnStretch(1, 1)
        panel_layout.addLayout(form_layout)

        output_row = QHBoxLayout()
        output_title = QLabel("PASSWORD")
        output_title.setFont(QFont(FONT_NAME, 15, QFont.Bold))
        output_row.addWidget(output_title)

        self.output_label = QLineEdit()
        self.output_label.setObjectName("outputField")
        self.output_label.setReadOnly(True)
        self.output_label.setFont(QFont(FONT_NAME, 20))
        self.output_label.setStyleSheet("font-size: 11pt; font-weight: 100;")
        self.output_label.setMinimumHeight(40)
        output_row.addWidget(self.output_label)

        panel_layout.addLayout(output_row)
        panel_layout.addSpacing(10)

        self.generate_btn = QPushButton("GENERATE PASSWORD")
        self.generate_btn.setObjectName("primaryButton")
        self.generate_btn.clicked.connect(self.generate_password)
        self.generate_btn.setFont(QFont(FONT_NAME, 14))
        self.generate_btn.setMinimumHeight(36)

        self.copy_btn = QPushButton("COPY")
        self.copy_btn.setObjectName("secondaryButton")
        self.copy_btn.clicked.connect(self.copy_to_clipboard)
        self.copy_btn.setMinimumHeight(36)

        self.clear_btn = QPushButton("CLEAR")
        self.clear_btn.setObjectName("secondaryButton")
        self.clear_btn.clicked.connect(self.clear_fields)
        self.clear_btn.setMinimumHeight(36)

        self.salt_test_btn = QPushButton("SALT STRENGTH TEST")
        self.salt_test_btn.setObjectName("secondaryButton")
        self.salt_test_btn.clicked.connect(self.open_salt_strength_tester)
        self.salt_test_btn.setMinimumHeight(36)

        self.access_btn = QPushButton("ACCESS STORED PASSWORDS")
        self.access_btn.setObjectName("secondaryButton")
        self.access_btn.clicked.connect(self.access_stored_passwords)
        self.access_btn.setMinimumHeight(36)

        self.change_master_btn = QPushButton("CHANGE MASTER KEY")
        self.change_master_btn.setObjectName("secondaryButton")
        self.change_master_btn.clicked.connect(self.change_master_password)
        self.change_master_btn.setMinimumHeight(36)

        self.clear_db_btn = QPushButton("CLEAR DATABASE")
        self.clear_db_btn.setObjectName("dangerButton")
        self.clear_db_btn.clicked.connect(self.clear_database)
        self.clear_db_btn.setMinimumHeight(36)

        self.delete_btn = QPushButton("DELETE STORED PASSWORD")
        self.delete_btn.setObjectName("dangerButton")
        self.delete_btn.clicked.connect(self.delete_password)
        self.delete_btn.setMinimumHeight(36)

        self.docs_btn = QPushButton("DOCUMENTATION")
        self.docs_btn.setObjectName("secondaryButton")
        self.docs_btn.clicked.connect(self.open_about_window)
        self.docs_btn.setMinimumHeight(36)

        buttons_grid = QGridLayout()
        buttons_grid.setHorizontalSpacing(18)
        buttons_grid.setVerticalSpacing(18)

        buttons_grid.addWidget(self.generate_btn, 0, 0)
        buttons_grid.addWidget(self.copy_btn, 0, 1)
        buttons_grid.addWidget(self.clear_btn, 0, 2)
        buttons_grid.addWidget(self.salt_test_btn, 1, 0)
        buttons_grid.addWidget(self.access_btn, 1, 1)
        buttons_grid.addWidget(self.change_master_btn, 1, 2)
        buttons_grid.addWidget(self.clear_db_btn, 2, 0)
        buttons_grid.addWidget(self.delete_btn, 2, 1)
        buttons_grid.addWidget(self.docs_btn, 2, 2)

        buttons_grid.setColumnStretch(0, 1)
        buttons_grid.setColumnStretch(1, 1)
        buttons_grid.setColumnStretch(2, 1)
        buttons_grid.setRowStretch(0, 1)
        buttons_grid.setRowStretch(1, 1)
        buttons_grid.setRowStretch(2, 1)

        panel_layout.addLayout(buttons_grid, 1)

        root_layout.addWidget(self.panel, 1)

    def _apply_theme(self):
        self.setStyleSheet(
            """
            QMainWindow#appWindow {
                background: #030303;
            }
            QWidget#rootCanvas {
                background: qradialgradient(
                    cx: 0.5, cy: 0.16, radius: 1.2,
                    fx: 0.5, fy: 0.16,
                    stop: 0 #1a1a1a,
                    stop: 0.45 #0d0d0d,
                    stop: 1 #020202
                );
            }
            QWidget {
                color: #f2f2f2;
                font-family: Quantico;
            }
            QWidget#heroReserve {
                background-color: rgba(6, 6, 6, 0.52);
                border: 1px solid #2f2f2f;
                border-radius: 14px;
            }
            QLabel#dragonAscii {
                color: #b8b8b8;
            }
            QLabel#heroTitleLabel {
                color: #ffffff;
                letter-spacing: 2px;
            }
            QLabel#heroTaglineLabel {
                color: #a6a6a6;
                letter-spacing: 4px;
            }
            QWidget#glassPanel {
                background-color: rgba(8, 8, 8, 0.92);
                border: 1px solid #4d4d4d;
                border-radius: 16px;
            }
            QLineEdit, QTextEdit, QSpinBox {
                background: #0d0d0d;
                color: #f7f7f7;
                border: 1px solid #565656;
                border-radius: 8px;
                padding: 7px;
                font-size: 12pt;
                selection-background-color: #f2f2f2;
                selection-color: #101010;
            }
            QLineEdit:focus, QSpinBox:focus, QTextEdit:focus {
                border: 1px solid #dedede;
            }
            QLineEdit#outputField {
                font-size: 30pt;
                font-weight: 700;
                padding: 8px;
            }
            QCheckBox {
                spacing: 6px;
                font-size: 12pt;
                color: #ececec;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
                border: 1px solid #707070;
                border-radius: 4px;
                background: #0c0c0c;
            }
            QCheckBox::indicator:checked {
                background: #e7e7e7;
                border: 1px solid #ffffff;
            }
            QPushButton {
                background: #171717;
                color: #f3f3f3;
                border: 1px solid #5c5c5c;
                border-radius: 8px;
                padding: 4px 10px;
                font-size: 15pt;
                font-weight: 600;
            }
            QPushButton#primaryButton {
                background: #efefef;
                border: 1px solid #ffffff;
                color: #0f0f0f;
            }
            QPushButton#primaryButton:hover {
                background: #ffffff;
            }
            QPushButton#secondaryButton:hover {
                background: #242424;
            }
            QPushButton#dangerButton {
                background: #222222;
                border: 1px solid #8a8a8a;
                color: #f3f3f3;
            }
            QPushButton#dangerButton:hover {
                background: #303030;
            }
            QPushButton:pressed {
                background: #0e0e0e;
            }
            """
        )

    def showEvent(self, event):
        super().showEvent(event)
        if self._intro_started:
            return

        self._intro_started = True
        self._start_intro_animation()
        self._fit_dragon_to_hero()
        self.hero_wave_timer.start()

    def _start_intro_animation(self):
        widgets = [self.panel]

        for idx, widget in enumerate(widgets):
            effect = QGraphicsOpacityEffect(widget)
            widget.setGraphicsEffect(effect)
            effect.setOpacity(0.0)

            animation = QPropertyAnimation(effect, b"opacity", self)
            animation.setDuration(420)
            animation.setStartValue(0.0)
            animation.setEndValue(1.0)
            animation.setEasingCurve(QEasingCurve.OutCubic)
            self._intro_animations.append(animation)
            QTimer.singleShot(idx * 130, animation.start)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._fit_dragon_to_hero()

    def _fit_dragon_to_hero(self):
        target_width = max(220, int(self.hero_reserve.width() * 0.27))
        target_height = max(140, self.hero_reserve.height() - 28)

        def fit_ascii(label, lines):
            if not lines:
                return

            best_size = 7
            for point_size in range(12, 6, -1):
                test_font = QFont("Cascadia Mono", point_size)
                metrics = QFontMetrics(test_font)
                max_line_width = max(metrics.horizontalAdvance(line) for line in lines)
                total_height = metrics.lineSpacing() * len(lines)

                if max_line_width <= target_width and total_height <= target_height:
                    best_size = point_size
                    break

            label.setFont(QFont("Cascadia Mono", best_size))
            label.setText("\n".join(lines))

        fit_ascii(self.dragon_label, self._dragon_lines)
        fit_ascii(self.right_dragon_label, self._right_dragon_lines)

    def _update_hero_wave(self):
        # Thin scan-wave traveling left (dragon) -> right (title/tagline).
        self._wave_position += 0.024
        if self._wave_position > 1.95:
            self._wave_position = -0.85

        def wave_strength(target_pos):
            dist = target_pos - self._wave_position
            # Smaller denominator => thinner moving wave band.
            return math.exp(-((dist * dist) / 0.018))

        def mix_cyan(strength):
            # High contrast makes the thin wave visibly pop.
            base = (0, 82, 108)
            peak = (150, 255, 255)
            r = int(base[0] + (peak[0] - base[0]) * strength)
            g = int(base[1] + (peak[1] - base[1]) * strength)
            b = int(base[2] + (peak[2] - base[2]) * strength)
            return r, g, b

        dr, dg, db = mix_cyan(wave_strength(0.00))
        tr, tg, tb = mix_cyan(wave_strength(1.00))
        ar, ag, ab = mix_cyan(wave_strength(1.28))
        rr, rg, rb = mix_cyan(wave_strength(1.62))

        self.dragon_label.setStyleSheet(f"color: rgb({dr}, {dg}, {db});")
        self.hero_title_label.setStyleSheet(
            f"color: rgb({tr}, {tg}, {tb}); letter-spacing: 2px;"
        )
        self.hero_tagline_label.setStyleSheet(
            f"color: rgb({ar}, {ag}, {ab}); letter-spacing: 4px;"
        )
        self.right_dragon_label.setStyleSheet(f"color: rgb({rr}, {rg}, {rb});")


    def _toggle_word_visibility(self, checked):
        self.word_entry.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)

    def _toggle_salt_visibility(self, checked):
        self.salt_entry.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)

    def _load_dragon_lines(self):
        fallback = [
            "        [::::::::::::::::::::]",
            "     [:::: GODFREY DRAGON ::::]",
            "        [::::::::::::::::::::]",
        ]

        for candidate in (DRAGON_ART_FILE, BUNDLED_DRAGON_ART_FILE):
            if not os.path.exists(candidate):
                continue

            try:
                with open(candidate, "r", encoding="utf-8") as handle:
                    lines = [line.rstrip("\n") for line in handle]
            except (OSError, UnicodeError):
                continue

            if lines and any(line.strip() for line in lines):
                return lines

        return fallback

    def _load_right_dragon_lines(self):
        fallback = [
            "        [:::: RIGHT DRAGON ::::]",
            "        [:::::::::::::::::::::::]",
            "        [:::: PLACEHOLDER ::::::]",
        ]

        for candidate in (RIGHT_DRAGON_ART_FILE, BUNDLED_RIGHT_DRAGON_ART_FILE):
            if not os.path.exists(candidate):
                continue

            try:
                with open(candidate, "r", encoding="utf-8") as handle:
                    lines = [line.rstrip("\n") for line in handle]
            except (OSError, UnicodeError):
                continue

            if lines and any(line.strip() for line in lines):
                return lines

        return fallback

    def _update_length_control_state(self):
        all_four_enabled = (
            self.upper_check.isChecked()
            and self.lower_check.isChecked()
            and self.special_check.isChecked()
            and self.numeric_pin_check.isChecked()
        )
        self.length_label.setEnabled(all_four_enabled)
        self.length_spin.setEnabled(all_four_enabled)

    def _ask_secret(self, title, prompt):
        dialog = QInputDialog(self)
        dialog.setWindowTitle(title)
        dialog.setLabelText(prompt)
        dialog.setTextEchoMode(QLineEdit.Password)
        dialog.setOkButtonText("OK")
        dialog.setCancelButtonText("CANCEL")
        dialog.setStyleSheet(self._dialog_stylesheet())
        if dialog.exec():
            return dialog.textValue()
        return None

    def _show_text_dialog(self, title, content):
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        dialog.resize(850, 500)
        dialog.setStyleSheet(self._dialog_stylesheet())

        layout = QVBoxLayout(dialog)
        text = QTextEdit(dialog)
        text.setObjectName("docTextView")
        text.setReadOnly(True)
        text.setPlainText(content)
        layout.addWidget(text)

        close_btn = QPushButton("CLOSE", dialog)
        close_btn.setObjectName("secondaryButton")
        close_btn.clicked.connect(dialog.accept)
        layout.addWidget(close_btn)

        dialog.exec()

    def _show_error(self, title, message):
        self._show_message(QMessageBox.Critical, title, message)

    def _show_info(self, title, message):
        self._show_message(QMessageBox.Information, title, message)

    def _show_warning(self, title, message):
        self._show_message(QMessageBox.Warning, title, message)

    def _dialog_stylesheet(self):
        return """
            QDialog, QMessageBox, QInputDialog {
                background: #090909;
                color: #f2f2f2;
            }
            QLabel {
                color: #f2f2f2;
                font-size: 12pt;
            }
            QLineEdit, QTextEdit {
                background: #0d0d0d;
                color: #f6f6f6;
                border: 1px solid #5a5a5a;
                border-radius: 6px;
                padding: 6px;
                selection-background-color: #ededed;
                selection-color: #101010;
            }
            QTextEdit#docTextView {
                font-size: 16pt;
            }
            QListWidget {
                background: #0d0d0d;
                color: #f6f6f6;
                border: 1px solid #5a5a5a;
                border-radius: 6px;
                alternate-background-color: #151515;
                selection-background-color: #efefef;
                selection-color: #111111;
            }
            QListWidget::item {
                padding: 6px;
            }
            QListWidget::item:selected {
                background: #efefef;
                color: #111111;
            }
            QPushButton {
                background: #1b1b1b;
                color: #f2f2f2;
                border: 1px solid #696969;
                border-radius: 7px;
                padding: 6px 12px;
                min-width: 90px;
            }
            QPushButton:hover {
                background: #2a2a2a;
            }
        """

    def _show_message(self, icon, title, message):
        box = QMessageBox(self)
        box.setIcon(icon)
        box.setWindowTitle(title)
        box.setText(message)
        box.setStandardButtons(QMessageBox.Ok)
        box.setStyleSheet(self._dialog_stylesheet())
        box.setWindowModality(Qt.ApplicationModal)
        box.raise_()
        box.activateWindow()
        box.exec()

    @staticmethod
    def _unique_preserve_order(text):
        seen = set()
        out = []
        for ch in text:
            if ch not in seen:
                seen.add(ch)
                out.append(ch)
        return "".join(out)

    def _build_password_from_filters(
        self,
        final_password,
        hex_hash,
        target_length,
        use_upper,
        use_lower,
        use_special,
        use_numeric,
    ):
        if not (use_upper or use_lower or use_special or use_numeric):
            raise ValueError("ENABLE AT LEAST ONE OUTPUT TYPE.")

        all_four_enabled = use_upper and use_lower and use_special and use_numeric
        non_numeric_enabled = use_upper or use_lower or use_special

        # Numeric-only mode uses Argon2 hex hash -> decimal digits.
        if use_numeric and not non_numeric_enabled:
            decimal_source = str(int(hex_hash, 16)) if hex_hash else ""
            unique_digits = self._unique_preserve_order(decimal_source)
            if not unique_digits:
                raise ValueError("FAILED TO BUILD NUMERIC PIN.")
            return unique_digits[:target_length] if all_four_enabled else unique_digits

        filtered = []
        for ch in final_password:
            if ch.isupper() and use_upper:
                filtered.append(ch)
            elif ch.islower() and use_lower:
                filtered.append(ch)
            elif ch.isdigit() and use_numeric:
                filtered.append(ch)
            elif (not ch.isalnum()) and use_special:
                filtered.append(ch)

        filtered_str = "".join(filtered)
        if not filtered_str:
            raise ValueError("CURRENT FILTERS PRODUCED EMPTY OUTPUT. ENABLE MORE TYPES.")

        unique_filtered = self._unique_preserve_order(filtered_str)
        return unique_filtered[:target_length] if all_four_enabled else unique_filtered
    @staticmethod
    def _evaluate_salt_strength(salt):
        length = len(salt)
        has_lower = any(ch.islower() for ch in salt)
        has_upper = any(ch.isupper() for ch in salt)
        has_digit = any(ch.isdigit() for ch in salt)
        has_special = any(not ch.isalnum() and not ch.isspace() for ch in salt)
        has_space = any(ch.isspace() for ch in salt)

        score = 0
        if length >= 8:
            score += 2
        if 8 <= length <= 14:
            score += 2
        elif 15 <= length <= 20:
            score += 1

        if has_upper:
            score += 2
        if has_digit:
            score += 2
        if has_special:
            score += 2
        if has_lower:
            score += 1
        if length > 0 and not has_space:
            score += 1
        if length > 0 and (len(set(salt)) / length) < 0.5:
            score -= 1

        score = max(0, min(score, 10))

        if length < 8:
            label = "Too Short"
            color = "#ff7b7b"
            tip = "Minimum 8 characters required."
        elif has_upper and has_digit and has_special and 8 <= length <= 14:
            label = "Recommended"
            color = "#7fe2b0"
            tip = "Ideal balance: short, memorable, and strong."
        elif score >= 8:
            label = "Strong"
            color = "#8fd9ff"
            tip = "Strong salt. You can still keep it shorter (8-14) if needed."
        elif score >= 6:
            label = "Good"
            color = "#c3e88d"
            tip = "Add uppercase, number, and special char for best result."
        elif score >= 4:
            label = "Fair"
            color = "#ffd166"
            tip = "Needs more variety. Include uppercase, number, special."
        else:
            label = "Weak"
            color = "#ff9f6e"
            tip = "Use at least 8 chars with uppercase, number, special."

        if length > 14 and has_upper and has_digit and has_special:
            tip = "Secure, but longer than needed. 8-14 chars is enough here."

        return {
            "score": score,
            "label": label,
            "color": color,
            "tip": tip,
            "length_ok": length >= 8,
            "has_upper": has_upper,
            "has_digit": has_digit,
            "has_special": has_special,
            "has_space": has_space,
        }

    def open_salt_strength_tester(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Salt Strength Test")
        dialog.resize(560, 420)
        dialog.setStyleSheet(self._dialog_stylesheet())

        layout = QVBoxLayout(dialog)
        title = QLabel("Live Salt Strength Test")
        title.setFont(QFont(FONT_NAME, 13, QFont.Bold))
        layout.addWidget(title)

        subtitle = QLabel(
            "Target: 8-14 chars with uppercase + number + special character. "
            "Lowercase is optional bonus."
        )
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        salt_input = QLineEdit(dialog)
        salt_input.setPlaceholderText("Type your salt here...")
        salt_input.setFont(QFont(FONT_NAME, 11))
        layout.addWidget(salt_input)

        strength_label = QLabel("Strength: -")
        strength_label.setFont(QFont(FONT_NAME, 12, QFont.Bold))
        layout.addWidget(strength_label)

        score_label = QLabel("Score: 0/10")
        layout.addWidget(score_label)

        checks_label = QLabel("")
        checks_label.setWordWrap(True)
        checks_label.setTextFormat(Qt.PlainText)
        layout.addWidget(checks_label)

        tip_label = QLabel("")
        tip_label.setWordWrap(True)
        layout.addWidget(tip_label)

        close_btn = QPushButton("CLOSE", dialog)
        close_btn.setObjectName("secondaryButton")
        close_btn.clicked.connect(dialog.accept)
        layout.addWidget(close_btn)

        def update_strength(value):
            result = self._evaluate_salt_strength(value)
            strength_label.setText(f"Strength: {result['label']}")
            strength_label.setStyleSheet(f"color: {result['color']}; font-weight: 700;")
            score_label.setText(f"Score: {result['score']}/10")

            checks_label.setText(
                "Checklist:\n"
                f"Minimum 8 chars: {'OK' if result['length_ok'] else 'NO'}\n"
                f"Uppercase letter: {'OK' if result['has_upper'] else 'NO'}\n"
                f"Number: {'OK' if result['has_digit'] else 'NO'}\n"
                f"Special char: {'OK' if result['has_special'] else 'NO'}\n"
                f"Spaces: {'AVOID' if result['has_space'] else 'OK'}"
            )
            tip_label.setText(f"Tip: {result['tip']}")

        salt_input.textChanged.connect(update_strength)
        update_strength("")
        dialog.exec()

    def save_master_password(self, password):
        core_save_master_password(MASTER_KEY_FILE, password)

    def verify_master_password(self, password):
        return core_verify_master_password(MASTER_KEY_FILE, password)

    def read_password_store(self, master_password):
        return core_read_password_store(PASSWORD_STORE_FILE, master_password)

    def write_password_store(self, content, master_password):
        core_write_password_store(PASSWORD_STORE_FILE, content, master_password)

    def encrypt_existing_passwords(self, old_password, new_password):
        core_encrypt_existing_passwords(PASSWORD_STORE_FILE, old_password, new_password)

    def initialize_master(self):
        if not os.path.exists(MASTER_KEY_FILE):
            if os.path.exists(PASSWORD_STORE_FILE):
                self._show_error(
                    "SECURITY WARNING",
                    "THE MASTER KEY FILE IS MISSING.\nRESTORE THE MASTER KEY FILE TO CONTINUE.",
                )
                return False

            pwd = self._ask_secret("SETUP", "SET A MASTER KEY:")
            if pwd is None:
                return False

            pwd = pwd.strip()
            if not pwd:
                self._show_error("ERROR", "MASTER KEY CANNOT BE EMPTY.")
                return False

            try:
                self.save_master_password(pwd)
            except StorageWriteError as exc:
                self._show_error("ERROR", f"FAILED TO SAVE MASTER KEY:\n{exc}")
                return False

            self.master_password_cache[:] = [pwd]
            self._show_info("SUCCESS", "MASTER KEY SET SUCCESSFULLY")
            return True

        pwd = self._ask_secret("LOGIN", "ENTER YOUR MASTER KEY:")
        if not pwd:
            return False

        if self.verify_master_password(pwd):
            self.master_password_cache[:] = [pwd]
            return True

        self._show_error("ACCESS DENIED", "INVALID MASTER KEY")
        return False

    def change_master_password(self):
        old_pass = self._ask_secret("Authentication", "ENTER CURRENT MASTER KEY:")
        if not self.verify_master_password(old_pass):
            self._show_error("ERROR", "INCORRECT CURRENT MASTER KEY")
            return

        new_pass = self._ask_secret("NEW PASSWORD", "ENTER A NEW MASTER KEY:")
        if not new_pass:
            return

        try:
            self.save_master_password(new_pass)
            self.encrypt_existing_passwords(old_pass, new_pass)
        except StorageWriteError as exc:
            self._show_error("ERROR", f"FAILED TO UPDATE MASTER KEY:\n{exc}")
            return

        self.master_password_cache[0] = new_pass
        self._show_info("SUCCESS", "MASTER KEY UPDATED SUCCESSFULLY")

    def store_password(self, word, salt, password, master_password):
        line = f"Word: {word} | Salt: {salt} | Password: {password}\n"

        try:
            existing = self.read_password_store(master_password)
        except DecryptionError:
            existing = ""

        self.write_password_store(existing + line, master_password)

    @staticmethod
    def _parse_password_lines(content):
        return [line.strip() for line in content.splitlines() if line.strip()]

    def _open_password_list_dialog(self, title, password_list, allow_delete=False):
        working_list = list(password_list)
        changed = False

        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        dialog.resize(980, 560)
        dialog.setStyleSheet(self._dialog_stylesheet())

        layout = QVBoxLayout(dialog)

        search_label = QLabel("SEARCH")
        search_label.setFont(QFont(FONT_NAME, 12, QFont.Bold))
        layout.addWidget(search_label)

        search_entry = QLineEdit(dialog)
        search_entry.setPlaceholderText("Type to filter by word, salt, or password...")
        search_entry.setFont(QFont(FONT_NAME, 11))
        layout.addWidget(search_entry)

        status_label = QLabel("")
        status_label.setFont(QFont(FONT_NAME, 10))
        layout.addWidget(status_label)

        list_widget = QListWidget(dialog)
        list_widget.setFont(QFont(FONT_NAME, 10))
        list_widget.setAlternatingRowColors(True)
        layout.addWidget(list_widget, 1)

        selected_label = QLabel("SELECTED ENTRY")
        selected_label.setFont(QFont(FONT_NAME, 11, QFont.Bold))
        layout.addWidget(selected_label)

        selected_view = QTextEdit(dialog)
        selected_view.setReadOnly(True)
        selected_view.setFont(QFont(FONT_NAME, 10))
        selected_view.setPlaceholderText("Click a list item, then select any part with mouse.")
        selected_view.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard)
        selected_view.setMinimumHeight(110)
        layout.addWidget(selected_view)

        button_row = QHBoxLayout()
        button_row.addStretch(1)

        delete_btn = None
        if allow_delete:
            delete_btn = QPushButton("DELETE SELECTED", dialog)
            delete_btn.setObjectName("dangerButton")
            button_row.addWidget(delete_btn)

        close_btn = QPushButton("CLOSE", dialog)
        close_btn.setObjectName("secondaryButton")
        close_btn.clicked.connect(dialog.accept)
        button_row.addWidget(close_btn)

        layout.addLayout(button_row)

        def update_selected_preview():
            item = list_widget.currentItem()
            selected_view.setPlainText(item.text() if item is not None else "")

        def refresh_list(query_text):
            query = query_text.strip().casefold()
            list_widget.clear()
            shown = 0

            for idx, line in enumerate(working_list):
                if not query or query in line.casefold():
                    item = QListWidgetItem(line)
                    item.setData(Qt.UserRole, idx)
                    list_widget.addItem(item)
                    shown += 1

            status_label.setText(f"SHOWING {shown} OF {len(working_list)} STORED PASSWORDS")

            if delete_btn is not None:
                delete_btn.setEnabled(shown > 0)

            if shown > 0:
                list_widget.setCurrentRow(0)
            else:
                selected_view.clear()

            update_selected_preview()

        def delete_selected():
            nonlocal changed

            item = list_widget.currentItem()
            if item is None:
                self._show_warning("SELECT PASSWORD", "CLICK A PASSWORD ENTRY TO DELETE.")
                return

            source_index = item.data(Qt.UserRole)
            if source_index is None or source_index >= len(working_list):
                self._show_warning("ERROR", "UNABLE TO RESOLVE SELECTED PASSWORD ENTRY.")
                return

            working_list.pop(source_index)
            changed = True
            refresh_list(search_entry.text())

            if not working_list:
                self._show_info("INFO", "NO PASSWORDS LEFT IN THE LIST.")

        search_entry.textChanged.connect(refresh_list)
        list_widget.currentItemChanged.connect(lambda _current, _previous: update_selected_preview())

        if delete_btn is not None:
            delete_btn.clicked.connect(delete_selected)

        refresh_list("")
        dialog.exec()
        return working_list, changed

    def access_stored_passwords(self):
        entered = self._ask_secret("AUTHENTICATE", "ENTER MASTER KEY TO ACCESS PASSWORDS:")
        if not self.verify_master_password(entered):
            self._show_error("ERROR", "INVALID MASTER KEY")
            return

        if not os.path.exists(PASSWORD_STORE_FILE):
            self._show_info("INFO", "NO PASSWORDS STORED YET.")
            return

        try:
            content = self.read_password_store(entered)
        except DecryptionError:
            self._show_error("ERROR", "FAILED TO DECRYPT PASSWORD FILE.")
            return

        password_list = self._parse_password_lines(content)
        if not password_list:
            self._show_info("INFO", "NO PASSWORDS STORED YET.")
            return

        self._open_password_list_dialog("STORED PASSWORDS", password_list, allow_delete=False)

    def delete_password(self):
        entered = self._ask_secret("AUTHENTICATE", "ENTER MASTER KEY TO DELETE A PASSWORD:")
        if not self.verify_master_password(entered):
            self._show_error("ERROR", "INVALID MASTER KEY")
            return

        if not os.path.exists(PASSWORD_STORE_FILE):
            self._show_info("INFO", "NO PASSWORD STORED YET.")
            return

        try:
            content = self.read_password_store(entered)
        except DecryptionError:
            self._show_error("ERROR", "FAILED TO DECRYPT PASSWORD FILE.")
            return

        password_list = self._parse_password_lines(content)
        if not password_list:
            self._show_info("INFO", "NO PASSWORD STORED YET.")
            return

        updated_list, changed = self._open_password_list_dialog(
            "DELETE STORED PASSWORDS", password_list, allow_delete=True
        )
        if not changed:
            return

        updated_content = "\n".join(updated_list)
        if updated_content:
            updated_content += "\n"

        try:
            self.write_password_store(updated_content, entered)
        except StorageWriteError as exc:
            self._show_error("ERROR", f"FAILED TO UPDATE PASSWORD FILE:\n{exc}")
            return

        deleted_count = len(password_list) - len(updated_list)
        self._show_info("SUCCESS", f"{deleted_count} PASSWORD(S) DELETED SUCCESSFULLY")

    def _type_tick(self):
        if self._typing_index >= len(self._typing_text):
            self.typing_timer.stop()
            return

        self._typing_index += 1
        self.output_label.setText(self._typing_text[: self._typing_index])

    def type_password(self, password):
        self._typing_text = password
        self._typing_index = 0
        self.output_label.setText("")
        self.typing_timer.start()

    def generate_password(self):
        word = self.word_entry.text().strip()
        salt = self.salt_entry.text()

        use_upper = self.upper_check.isChecked()
        use_lower = self.lower_check.isChecked()
        use_special = self.special_check.isChecked()
        use_numeric = self.numeric_pin_check.isChecked()
        target_length = self.length_spin.value()

        try:
            artifacts = generate_password_artifacts(word, salt)
            filtered_password = self._build_password_from_filters(
                final_password=artifacts["final_password"],
                hex_hash=artifacts["hex_hash"],
                target_length=target_length,
                use_upper=use_upper,
                use_lower=use_lower,
                use_special=use_special,
                use_numeric=use_numeric,
            )

            self.type_password(filtered_password)
            self.store_password(word, salt, filtered_password, self.master_password_cache[0])
        except ValueError as exc:
            msg = str(exc)
            if "BOTH WORD AND SALT" in msg:
                title = "MISSING INPUT"
            elif "AT LEAST 8 CHARACTERS" in msg:
                title = "WEAK SALT"
            else:
                title = "INVALID SETTINGS"
            self._show_warning(title, msg)
        except Argon2Error as exc:
            self._show_error("ERROR", f"ARGON2 FAILED: {exc}")
        except StorageWriteError as exc:
            self._show_error("ERROR", f"FAILED TO STORE PASSWORD:\n{exc}")

    def clear_fields(self):
        self.word_entry.clear()
        self.salt_entry.clear()
        self.output_label.clear()

    def copy_to_clipboard(self):
        password = self.output_label.text()
        if password:
            QApplication.clipboard().setText(password)
            self._show_info("COPIED", "PASSWORD COPIED TO CLIPBOARD!")

    def clear_database(self):
        master_pass = self._ask_secret(
            "AUTHENTICATION",
            "ENTER MASTER KEY TO CLEAR DATABASE:\n\nWARNING: THIS WILL DELETE ALL STORED PASSWORDS.",
        )

        if not self.verify_master_password(master_pass):
            self._show_error("ERROR", "INVALID MASTER KEY")
            return

        if os.path.exists(PASSWORD_STORE_FILE):
            os.remove(PASSWORD_STORE_FILE)
            self._show_info("SUCCESS", "ALL THE PASSWORDS ARE WIPED.")
        else:
            self._show_info("INFO", "DATABASE ALREADY EMPTY.")

    def open_about_window(self):
        self._show_text_dialog(
            "DOCUMENTATION",
            "\n".join(
                [
                  '''  ⠀⠀⠈⠉⠉⠉⠉⠉⠉⠉⠉⠙⠛⠛⠛⠛⠛⠻⠿⠷⠶⢶⣶⣶⣤⣤⣤⣄⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠛⠛⠛⠛⠛⠿⠿⣿⣶⣶⣶⣶⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠛⠻⠿⣿⣷⣦⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⣀⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣄⣀⣀⣈⣉⠛⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣀⣀⣤⣤⣴⠶⠶⠿⠿⠛⠛⠛⠛⠛⠋⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠛⠛⠛⠛⠻⠿⠧⢸⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣤⣤⠶⠶⠟⠛⠛⠋⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣤⣤⣤⣤⣴⣶⣶⡎⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣠⣤⣴⣶⣶⣿⣿⣿⠿⠿⠿⠿⠟⠛⠛⠓⠘⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣶⣶⣿⠿⠿⠛⠛⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠂⠄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⣶⠿⠟⠛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣷⣦⣤⣤⣤⣤⣤⣄⣀⣀⠀⠀⠀⠀⠈⠑⠢⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⡶⠿⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣿⣿⣿⣿⠿⠿⠿⠿⢿⣿⣿⣿⣿⣷⣶⣼⣄⠀⢠⠈⠑⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠴⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⡿⠟⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠛⠻⢿⣿⣿⣾⣷⣄⢤⠙⢦⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠄⠊⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠿⢿⣿⣷⣤⣉⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⣿⣿⣿⢷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⢿⣿⣷⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠻⣿⣦⣄⣀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⠟⠉⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣿⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⣷⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⠿⣿⣿⣿⣿⣿⣶⣶⣶⣶⣶⣶⣶⣶⣦⣤⣤⣤⣤⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠉⠛⠛⠛⠛⠛⠛⠛⠻⠿⠿⢿⣿⣿⣿⣿⣿⠿⢷⣶⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠛⠿⢿⣶⣤⡉⠙⠻⢷⣦⣄⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⢿⣦⡄⠀⠈⠙⠿⣦⡀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣦⡀⠀⠀⠈⠻⣦⡀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣷⡄⠀⠀⠀⠈⢿⡄⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣿⡄⠀⠀⠀⠀⢻⡄
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⡀⠀⠀⠀⠀⢣
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣇⠀⠀⠀⠀⠘
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⡄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣇⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠀⠀⠀⠀
This project is open source under the "Do whatever, but please give me credits" license.

Disclaimer: This tool is solely built on purpose of education. IF YOUR INTENT IS BAD, YOUR FBI AGENT IS GOING TO RAID YOUR HOUSE TONIGHT. But I definitely recommend you to collaborate and contribute to become a hero for this society.

This tool was made by a hacker, to protect you from hackers.

Built By DISHANT alias RETZ. So don't try to claim or steal it or else the First Elden lord will make you cower in fear.

Just like you, even I never remembered my passwords. But I never trusted myself with a password manager. You ever trusted a cloud-based password manager, a thing that is literally CONNECTED to the internet??? Bro your entire digital vault is sitting on someone else's server, and you can't even peek under the hood to see what's really going on.

I know you can't sniff networks, but I can; that's what forces me to stay offline.

I agree we will be going passwordless in just few years, the quantum computing is gonna break our encryption systems, and hashing algorithms but till then we cannot just let the hackers to harvest our data for tomorrow.

Let's cut the crap and go to main documentation.

Godfrey Keygen is a secure and offline Python-based password manager built with Tkinter. It focuses on extremely secure password generation, functionality and a friendly user experience.

THE BASIC IDEA OF THIS TOOL IS FOR THE USER TO REMEMBER ONLY THE USERNAME AND A SINGLE SALT PHRASE, AND YOU SHALL BECOME THE ALMIGHTY OF ALL PASSWORDS.

Technologies used:

Python

Tkinter for GUI

Argon2 (argon2-cffi library)

Cryptography module

Base encoding libraries

AUTHENTICATION:

A new user is prompted with a dialog box to set up a 'Master Key'. User can set the 'Master Key' as per their will. The 'Master Key' is stored in a KEY file encrypted with AES-256 GCM Encryption.

The tool and author expects user to keep master key as unique and simple. And next time user returns, the tool will ask user to authenticate with the master key as set previously.

Master key can also be changed, by entering the current master key.

The master key will be used for following purposes:

Authentication

Accessing stored passwords

Deleting stored passwords

Deleting entire database that includes all stored passwords

Update the master key with new

WORKING AND FUNCTIONALITY:

This tool relies on the core concept of cryptography i.e hashing.

A secure password is generated via accepting a word from the user and hashing it with a custom salt that user chooses.

The flowchart towards the secure password generation is as follows:

➤ A "WORD" and "SALT" is accepted from user.
➤ Argon2-cffi algorithm hashes the word along with its salt.
➤ The generated "Binary Hash" is converted to "Hexadecimal Hash".
➤ The "Hexadecimal Hash" is then reversed.
➤ The reversed Hex Hash is encoded with Base-91 encoding.
➤ The Base-91 encoding is entropic as it contains numbers, both uppercase, lowercase and special characters.
➤ And the reverse Base-91 string becomes our password.
➤ To this password generation, endless possibilities exist, just so you know sky is the limit.
➤ You are free to try your own mind bending techniques to generate strongest possible password.

TOOL SETTINGS:

Memory-cost = 2^17 (128MB)
The tool uses 128 megabytes of RAM per hash. Attacker's GPUs struggle to crack due to this setting. The melting heat of their GPUs will definitely cause global warming.

Parallelism = 4 threads in parallel
Makes it difficult to attack in parallel. I don't fight solo, 4 blades, all single handedly.

hash-len = 17 bytes (136 bits)
This will give us 2^136 possible combinations, meaning hacker has to try 87 OCTILLION OCTILLION possibilities. HAHA!!! Prevents the possibility of two different inputs giving out same hash input i.e Collision.

Time-cost = 15 iterations
Each 'WORD' goes through 15 cycles of being hashed. I'll make you feel the pain, each cycle.

STANDARD FORMAT:

There is no standard format to choose your 'WORD' and 'SALT'.

For those who did not understand what does 'WORD' and 'SALT' mean, here is entire explanation for them.

Consider 'WORD' as a normal word which is to be processed to form a hash.

(HASH: Hash is a one way mathematical function, that is widely used in world of internet, especially for storing confidential stuff like passwords.)

'SALT' is a random string, or say a key which we add in process of forming hash to make it difficult to be broken by hackers.

The more random is 'SALT' the more entropy is generated and generated hash becomes almost crack-proof.

Say if it is a password for email, your email username becomes your password itself, but slightly changed.

Example: Let's say there is an email of a person peterparker123@gmail.com
.

So making it simplest, our 'WORD' becomes peterparker.

You can keep anything as 'WORD' whatever you feel secure.

That's it.

Talking about salt, you must keep it VERY SECRET.

MOST IMPORTANTLY, IT HAS TO BE MINIMUM 8 CHARACTERS.

Now it is upto you what efficient salt standard you choose.

But make sure to include BOTH LOWER AND UPPERCASE CHARACTERS, SPECIAL CHARACTERS AND NUMBERS.

You worried huh?

Don't be.

You just have to remember that one single phrase or lyrics or any line that only you must know.

It has to be so secret that not even GOD could guess it.

That could be a childhood joke or whatever you can think of.

Use that one single phrase of your life as a 'Salt' in every password.

And you will be good in every possible way.

This is optional yet safest way.

If you have big brain, keep different salt for every different password.

Because the motive of this tool is to make you remember only your username and a single salt phrase.

And you are done, you have every single password in your fist.

Password options:- 

1)Uppercase characters

2)Lowercase characters

3)Special characters

4)Numbers

➤Using all 4 options will allow full length generated password to be stored.

➤Using only Uppercase Characters will only print uppercase characters from original generated password.

➤Using only Lowercase Characters will only print lowercase characters from original generated password.

➤Using only Special Characters will only print special characters from original generated password.

➤Using only Number option will allow the whole generated hex hash to be converted to integer in order to make a PIN.

➤Variety of choices can be made for a unique and flexible password generation.


Note:- The password length is only allowed when all 4 options are enabled.

HOW SECURE YOU ARE:

You will be immune to these attacks:

1) Rainbow Table Attacks

➤ In this attack, attacker uses a precomputed list of hashes for common passwords, which if matched the password is compromised.

Since our tool uses unique username everytime and a very secret salt phrase (complex than nuclear codes), a very unique hash is generated each time, which is impossible to be precomputed.

It will take THOUSAND TO MILLION years to get that hash to be guessed.

2) Brute Force Attack

➤ This attack is nothing but a joke for our tool, the time it will take to guess the password will be around extinction of universe.

3) Reverse Engineering

➤ If your system gets stolen along with this tool and saved passwords, not an issue.

The tool is completely offline.

The password is encrypted with master key, which the User only knows.

So there's no way attacker is going to waste his time on salvaging the encrypted unreadable gibberish.

If the system is gone permanently, you get another system, download this tool and re-generate your passwords with same 'WORD' and 'SALT'.

DAMNN!!! SUCH A SUPER POWER. ISN'T IT

And no attacker could actually break it using normal systems, even a supercomputer would cry doing it.

Just quantum computers are yet to take that challenge.

THINGS YOU NEED TO REMEMBER:

➤ Nothing in the world exist is hack-proof.
➤ You own your security, you are responsible for your actions, so always be cautious in the world of internet.
➤ Always keep an eye on emails and login alerts of different platforms.
➤ Never login your primary email on unknown computers.
➤ Remove email access from the apps or services which were not used for a long time.

This isn't just a password tool. It's a fortress built with logic, layered in encryption.

I didn't make it only to generate password, but also manage the passwords and store it securely.

REMEMBER THE RECIPE, SALT IT AS PER YOUR TASTE, ENJOY THE DISH.'''
                    
                ]
            ),
        )


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("GODFREY KEYGEN")

    window = GodfreyWindow()
    if not window.initialize_master():
        return 0

    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())





