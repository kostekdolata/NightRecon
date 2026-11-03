"""Optional Qt visual shell for Red Night's approved black/crimson design.

This module is a display-only UI prototype. It does not execute scans.
PySide6 is deliberately imported only when the shell is launched.
"""
from __future__ import annotations

NAVIGATION = (
    "Operations", "Target Intelligence", "Engine Console", "Validation Lab",
    "Findings", "Reporting", "Audit & Control",
)
COLORS = {
    "background": "#07080D",
    "panel": "#11151D",
    "panel_alt": "#171C26",
    "accent": "#FF304D",
    "accent_dark": "#8A1426",
    "text": "#F3F5F9",
    "muted": "#A5ADB9",
    "border": "#2B303A",
}
STYLESHEET = """
QMainWindow, QScrollArea, QWidget#root { background: #07080D; color: #F3F5F9; }
QWidget#sidebar { background: #0C1017; border-right: 1px solid #2B303A; }
QWidget#content { background: #07080D; }
QLabel { color: #F3F5F9; background: transparent; }
QLabel#brand { font-size: 28px; font-weight: 800; }
QLabel#heading { font-size: 23px; font-weight: 700; }
QLabel#eyebrow { font-size: 11px; letter-spacing: 3px; color: #A5ADB9; }
QLabel#metricValue { font-size: 29px; font-weight: 750; color: #F3F5F9; }
QLabel#metricCaption { font-size: 12px; color: #A5ADB9; }\nQLabel#sectionTitle { font-size: 15px; font-weight: 700; }\nQLineEdit { padding: 10px 14px; border: 1px solid #242A34; border-radius: 12px; background: #151922; color: #E5E9F0; }\nQFrame#topbar { background: #090B10; }
QFrame#card { background: #11151D; border: 1px solid #2B303A; border-radius: 14px; }
QFrame#hero { background: #200D19; border: 1px solid #59202B; border-radius: 15px; }
QPushButton { background: #171C26; color: #F3F5F9; border: 1px solid #2B303A;
    border-radius: 9px; padding: 11px 14px; text-align: left; }
QPushButton:hover { border-color: #FF304D; }
QPushButton:checked { color: #FF4A65; background: #2D1520; border-left: 3px solid #FF304D; }
QPushButton#primary { background: #8A1426; color: white; border-color: #FF304D; }
QPushButton:disabled { color: #86909D; background: #191C24; border-color: #343843; }
QScrollArea { border: 0; }
QTextEdit { background: #10141C; color: #D9E2EE; border: 1px solid #2B303A;
    border-radius: 9px; font-family: Consolas, monospace; font-size: 12px; }
QSplitter::handle { background: #2B303A; }
"""


def build_window():
    from PySide6.QtCore import Qt, QPointF
    from PySide6.QtGui import QColor, QPainter, QRadialGradient, QLinearGradient, QPen, QPainterPath
    from PySide6.QtWidgets import (
        QButtonGroup, QFrame, QHBoxLayout, QLabel, QMainWindow, QPushButton,
        QScrollArea, QSplitter, QTextEdit, QVBoxLayout, QWidget, QGridLayout, QLineEdit,
    )

    class MoonHero(QFrame):
        """Scalable, locally rendered moon-and-ridge brand atmosphere."""
        def __init__(self):
            super().__init__()
            self.setObjectName("hero")
            self.setMinimumHeight(215)

        def paintEvent(self, event):
            super().paintEvent(event)
            painter = QPainter(self)
            painter.setRenderHint(QPainter.Antialiasing)
            rect = self.rect()
            backdrop = QLinearGradient(0, 0, rect.width(), rect.height())
            backdrop.setColorAt(0, QColor("#10111A"))
            backdrop.setColorAt(0.6, QColor("#2C0C19"))
            backdrop.setColorAt(1, QColor("#090B12"))
            painter.fillRect(rect, backdrop)
            x, y = rect.width() * 0.76, rect.height() * 0.39
            radius = min(rect.height() * 0.32, rect.width() * 0.15)
            glow = QRadialGradient(QPointF(x, y), radius * 1.8)
            glow.setColorAt(0, QColor(255, 39, 59, 185))
            glow.setColorAt(0.45, QColor(222, 30, 53, 92))
            glow.setColorAt(1, QColor(150, 0, 25, 0))
            painter.setPen(Qt.NoPen)
            painter.setBrush(glow)
            painter.drawEllipse(QPointF(x, y), radius * 1.8, radius * 1.8)
            painter.setBrush(QColor("#F33A52"))
            painter.drawEllipse(QPointF(x, y), radius, radius)
            painter.setBrush(QColor(90, 8, 25, 90))
            for dx, dy, size in ((-0.36, -0.16, 0.14), (0.27, 0.24, 0.19),
                                 (0.12, -0.31, 0.11), (-0.08, 0.18, 0.13)):
                painter.drawEllipse(QPointF(x + dx * radius, y + dy * radius),
                                    radius * size, radius * size)
            ridge = QPainterPath()
            ridge.moveTo(0, rect.height())
            for px, py in ((0, .88), (.1, .77), (.2, .89), (.29, .65),
                           (.37, .79), (.48, .61), (.60, .83), (.71, .68),
                           (.8, .85), (.9, .71), (1, .87)):
                ridge.lineTo(rect.width() * px, rect.height() * py)
            ridge.lineTo(rect.width(), rect.height())
            ridge.closeSubpath()
            painter.fillPath(ridge, QColor("#05070D"))
            painter.setPen(QPen(QColor("#D72B43"), 2))
            painter.drawLine(0, rect.height()-3, rect.width(), rect.height()-3)
            painter.end()

    class RedNightWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("Red Night | Professional Assessment Operations")
            self.resize(1440, 900)
            self.setStyleSheet(STYLESHEET)
            central = QWidget()
            central.setObjectName("root")
            self.setCentralWidget(central)
            root_layout = QHBoxLayout(central)
            root_layout.setContentsMargins(0, 0, 0, 0)
            root_layout.setSpacing(0)

            splitter = QSplitter(Qt.Horizontal)
            root_layout.addWidget(splitter)

            sidebar = QWidget()
            sidebar.setObjectName("sidebar")
            sidebar_layout = QVBoxLayout(sidebar)
            sidebar_layout.setContentsMargins(18, 24, 18, 20)
            sidebar_layout.setSpacing(12)
            brand = QLabel("RED NIGHT")
            brand.setObjectName("brand")
            brand.setStyleSheet("color: #FF304D")
            sidebar_layout.addWidget(brand)
            subtitle = QLabel("PROFESSIONAL SECURITY OPERATIONS")
            subtitle.setObjectName("eyebrow")
            subtitle.setWordWrap(True)
            sidebar_layout.addWidget(subtitle)
            sidebar_layout.addSpacing(18)
            self.navigation = QButtonGroup(self)
            self.navigation.setExclusive(True)
            for index, label in enumerate(NAVIGATION):
                button = QPushButton(label)
                button.setCheckable(True)
                button.setChecked(index == 0)
                self.navigation.addButton(button, index)
                sidebar_layout.addWidget(button)
            sidebar_layout.addStretch()
            sidebar_layout.addWidget(QLabel("RED NIGHT  /  QT VISUAL PREVIEW"))
            splitter.addWidget(sidebar)

            scroller = QScrollArea()
            scroller.setWidgetResizable(True)
            scroller.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
            scroller.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
            content = QWidget()
            content.setObjectName("content")
            layout = QVBoxLayout(content)
            layout.setContentsMargins(25, 28, 25, 28)
            layout.setSpacing(18)
            scroller.setWidget(content)
            splitter.addWidget(scroller)
            splitter.setSizes([250, 1190])
            splitter.setChildrenCollapsible(False)

            topbar = QFrame()
            topbar.setObjectName("topbar")
            top = QHBoxLayout(topbar)
            top.setContentsMargins(4, 0, 4, 0)
            heading = QLabel("Assessment Operations")
            heading.setObjectName("heading")
            top.addWidget(heading)
            top.addStretch()
            search = QLineEdit()
            search.setPlaceholderText("Search workspace... (preview)")
            search.setReadOnly(True)
            search.setMaximumWidth(290)
            top.addWidget(search)
            badge = QLabel("●  PREVIEW MODE")
            badge.setStyleSheet("color: #FF576B; padding-left: 16px; font-weight: bold;")
            top.addWidget(badge)
            layout.addWidget(topbar)

            hero = MoonHero()
            hero_layout = QVBoxLayout(hero)
            hero_layout.setContentsMargins(32, 28, 28, 27)
            hero_layout.setSpacing(11)
            tagline = QLabel("A U T H O R I S E D   S E C U R I T Y   O P E R A T I O N S")
            tagline.setObjectName("eyebrow")
            hero_layout.addWidget(tagline)
            hero_layout.addStretch()
            hero_title = QLabel("Red Night")
            hero_title.setObjectName("brand")
            hero_title.setStyleSheet(
                "color: #F5F6FA; font-size: 49px; font-weight: 800;")
            hero_layout.addWidget(hero_title)
            hero_text = QLabel("The night is under your control.")
            hero_text.setStyleSheet("color: #CAD0DB; letter-spacing: 2px; font-size: 13px;")
            hero_layout.addWidget(hero_text)
            layout.addWidget(hero)

            summary = QGridLayout()
            summary.setHorizontalSpacing(13)
            summary.setVerticalSpacing(13)
            for col, (value, title, symbol) in enumerate((
                ("—", "DISCOVERED ASSETS", "◎"),
                ("—", "OPEN PORTS", "⌁"),
                ("—", "REVIEWED FINDINGS", "◇"),
                ("—", "ACTIVE ENGINES", "◈"),
            )):
                card = QFrame()
                card.setObjectName("card")
                card.setMinimumHeight(108)
                card_layout = QVBoxLayout(card)
                card_layout.setContentsMargins(18, 14, 18, 14)
                caption = QLabel(f"{symbol}    {title}")
                caption.setObjectName("metricCaption")
                card_layout.addWidget(caption)
                metric = QLabel(value)
                metric.setObjectName("metricValue")
                card_layout.addWidget(metric)
                accent_line = QFrame()
                accent_line.setFixedHeight(2)
                accent_line.setStyleSheet(
                    "background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
                    "stop:0 #FA304C,stop:0.55 #A21B35,stop:1 transparent);")
                card_layout.addWidget(accent_line)
                summary.addWidget(card, 0, col)
                summary.setColumnStretch(col, 1)
            layout.addLayout(summary)

            toolbar = QHBoxLayout()
            for label in ("RUN ALL", "CUSTOM ENGINES", "REVIEW PREFLIGHT"):
                control = QPushButton(label)
                control.setEnabled(False)
                control.setToolTip("Awaiting governed Qt integration")
                toolbar.addWidget(control)
            toolbar.addStretch()
            layout.addLayout(toolbar)

            lower = QSplitter(Qt.Horizontal)
            def make_panel(title):
                panel = QFrame()
                panel.setObjectName("card")
                inner = QVBoxLayout(panel)
                inner.setContentsMargins(18, 17, 18, 17)
                inner.setSpacing(13)
                caption = QLabel(title)
                caption.setObjectName("sectionTitle")
                inner.addWidget(caption)
                return panel, inner

            telemetry, telemetry_layout = make_panel("Assessment Telemetry")
            telemetry_layout.addWidget(QLabel("Illustrative activity  •  Not live scan data"))
            visual = QFrame()
            visual.setFixedHeight(135)
            visual.setStyleSheet(
                "background: qlineargradient(x1:0,y1:1,x2:1,y2:0,"
                "stop:0 #130C17,stop:0.5 #2D111D,stop:1 #121821);"
                "border: 1px solid #38202B; border-radius: 9px;")
            telemetry_layout.addWidget(visual)
            telemetry_layout.addWidget(QLabel("●  DISCOVERY      ●  VALIDATION      ●  REPORTING"))
            telemetry_layout.addStretch()
            lower.addWidget(telemetry)

            activity, activity_layout = make_panel("Recent Activity")
            self.activity = QTextEdit()
            self.activity.setReadOnly(True)
            self.activity.setPlainText(
                "●  Workspace ready for operator review\\n\\n"
                "○  No engagement is connected\\n\\n"
                "○  No scan evidence has been loaded\\n\\n"
                "○  All execution controls are disabled")
            self.activity.setMinimumHeight(190)
            activity_layout.addWidget(self.activity)
            lower.addWidget(activity)

            tools, tools_layout = make_panel("Quick Tools")
            for label in ("◎  Run All", "⌁  Custom Engines",
                          "◇  Review Findings", "▤  Generate Report"):
                button = QPushButton(label)
                button.setEnabled(False)
                button.setToolTip("Not yet connected to the governed backend")
                tools_layout.addWidget(button)
            tools_layout.addStretch()
            lower.addWidget(tools)
            lower.setSizes([480, 350, 270])
            layout.addWidget(lower)

            notice = QLabel(
                "VISUAL PREVIEW  /  No live assessment data  /  "
                "Engagement authority required for execution")
            notice.setObjectName("eyebrow")
            notice.setWordWrap(True)
            layout.addWidget(notice)
            layout.addStretch()

            self._workspace_label = heading
            self.navigation.idClicked.connect(self._navigate)
            self.statusBar().showMessage("VISUAL PREVIEW  •  No live engagement  •  Execution disabled")

        def _navigate(self, index):
            self._workspace_label.setText(NAVIGATION[index])
            if index != 0:
                self.activity.setPlainText(
                    f"{NAVIGATION[index]} workspace is not yet wired to Qt.\n"
                    "No scan or modification has been performed.")
            else:
                self.activity.setPlainText(
                    "No engagement connected.\nNo live evidence has been loaded.")

    return RedNightWindow()


def main() -> None:
    from PySide6.QtWidgets import QApplication
    import sys
    app = QApplication.instance() or QApplication(sys.argv)
    window = build_window()
    window.show()
    app.exec()


if __name__ == "__main__":
    main()
