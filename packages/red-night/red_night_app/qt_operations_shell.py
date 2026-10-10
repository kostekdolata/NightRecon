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
QLabel#metricCaption { font-size: 12px; color: #A5ADB9; }
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
        QScrollArea, QSplitter, QTextEdit, QVBoxLayout, QWidget,
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

            heading = QLabel("Assessment Operations")
            heading.setObjectName("heading")
            layout.addWidget(heading)

            hero = MoonHero()
            hero_layout = QVBoxLayout(hero)
            hero_layout.setContentsMargins(28, 28, 28, 28)
            hero_layout.setSpacing(10)
            tagline = QLabel("THE NIGHT IS UNDER YOUR CONTROL")
            tagline.setObjectName("eyebrow")
            hero_layout.addWidget(tagline)
            hero_title = QLabel("Red Night")
            hero_title.setObjectName("brand")
            hero_title.setStyleSheet("color: #FF304D; font-size: 42px; font-weight: bold;")
            hero_layout.addWidget(hero_title)
            hero_text = QLabel(
                "Authorised reconnaissance • Evidence-led validation • Operator-controlled execution")
            hero_text.setWordWrap(True)
            hero_layout.addWidget(hero_text)
            layout.addWidget(hero)

            summary = QHBoxLayout()
            for value, title in (
                ("—", "DISCOVERED ASSETS"), ("—", "OPEN PORTS"),
                ("—", "REVIEWED FINDINGS"), ("—", "ACTIVE ENGINES"),
            ):
                card = QFrame()
                card.setObjectName("card")
                card_layout = QVBoxLayout(card)
                card_layout.setContentsMargins(17, 18, 17, 18)
                caption = QLabel(title)
                caption.setObjectName("metricCaption")
                card_layout.addWidget(caption)
                metric = QLabel(value)
                metric.setObjectName("metricValue")
                card_layout.addWidget(metric)
                summary.addWidget(card, 1)
            layout.addLayout(summary)

            sections = QSplitter(Qt.Horizontal)
            left = QFrame()
            left.setObjectName("card")
            left_layout = QVBoxLayout(left)
            left_layout.addWidget(QLabel("ASSESSMENT ORCHESTRATION"))
            left_layout.addWidget(QLabel(
                "Run All selects eligible approved engines. Custom allows operator selection."))
            left_layout.addWidget(QLabel("No engagement is currently attached to this preview."))
            start = QPushButton("Start Assessment — awaiting governed integration")
            start.setObjectName("primary")
            start.setEnabled(False)
            left_layout.addWidget(start)
            left_layout.addStretch()
            sections.addWidget(left)
            right = QFrame()
            right.setObjectName("card")
            right_layout = QVBoxLayout(right)
            right_layout.addWidget(QLabel("ENGINE READINESS"))
            for name, status in (
                ("Nmap", "Governed integration under validation"),
                ("Metasploit", "Planned — not executable"),
                ("Nuclei / ZAP / TShark", "Evidence imports / planned"),
            ):
                label = QLabel(f"{name}  •  {status}")
                label.setWordWrap(True)
                right_layout.addWidget(label)
            right_layout.addStretch()
            sections.addWidget(right)
            sections.setSizes([650, 500])
            layout.addWidget(sections)

            activity = QFrame()
            activity.setObjectName("card")
            activity_layout = QVBoxLayout(activity)
            activity_layout.addWidget(QLabel("OPERATIONAL ACTIVITY / EVIDENCE STREAM"))
            self.activity = QTextEdit()
            self.activity.setReadOnly(True)
            self.activity.setPlainText(
                "No engagement connected.\n"
                "No live evidence has been loaded.\n"
                "This Qt shell is intentionally non-operational.")
            self.activity.setMinimumHeight(180)
            activity_layout.addWidget(self.activity)
            layout.addWidget(activity)
            layout.addStretch()

            self.navigation.idClicked.connect(self._navigate)
            self.statusBar().showMessage("VISUAL PREVIEW  •  No live engagement  •  Execution disabled")

        def _navigate(self, index):
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
