"""Hintergrundausfuehrung.

``ssh-keygen -a 100`` braucht spuerbar Zeit; im Hauptthread wuerde das Fenster
einfrieren. Jede Operation der Kernschicht laeuft deshalb in einem
QThreadPool-Task, dessen Ergebnis per Signal in den GUI-Thread zurueckkommt.

Zwei Dinge sind hier bewusst so gebaut und duerfen nicht "vereinfacht" werden:

1. Lebensdauer. Der Aufrufer verwirft den Rueckgabewert von run_task. Ohne
   weitere Referenz wird der Task (und damit der Signal-Sender) unmittelbar
   nach dem Ende von run() freigegeben — noch nicht zugestellte, queued
   Signale sterben dann mit dem Sender, die Callbacks laufen nie, und eine
   per _busy() deaktivierte Oberflaeche bleibt fuer immer deaktiviert. Die
   Registry _ACTIVE haelt Task und Bruecke deshalb bis nach der Zustellung
   von done() am Leben; erst der done-Slot gibt beides frei.

2. Threadzugehoerigkeit. Die Callbacks werden nicht direkt mit den Signalen
   verbunden, sondern mit Slots der _Bridge — eines QObjects, das im
   GUI-Thread lebt. Verbindungen auf gebundene Methoden eines QObjects werden
   von Qt queued in dessen Thread zugestellt; damit laufen alle Callbacks
   garantiert im GUI-Thread, egal was fuer ein Callable uebergeben wurde.
"""

from __future__ import annotations

import traceback
from typing import Any, Callable

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal, Slot

#: Haelt (Bruecke, Task)-Paare am Leben, bis done() zugestellt wurde.
_ACTIVE: set["_Bridge"] = set()


class TaskSignals(QObject):
    finished = Signal(object)          # Rueckgabewert der Funktion
    failed = Signal(str, str)          # Kurztext, Details
    done = Signal()                    # immer, als letztes


class Task(QRunnable):
    def __init__(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        super().__init__()
        # Kein autoDelete: die Lebensdauer verwaltet die Registry, nicht der
        # Threadpool. Sonst stirbt der Signal-Sender vor der Zustellung.
        self.setAutoDelete(False)
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.signals = TaskSignals()

    @Slot()
    def run(self) -> None:
        try:
            result = self.func(*self.args, **self.kwargs)
        except Exception as exc:  # noqa: BLE001 — bewusst alles abfangen
            self.signals.failed.emit(str(exc), traceback.format_exc())
        else:
            self.signals.finished.emit(result)
        finally:
            self.signals.done.emit()


class _Bridge(QObject):
    """Nimmt die Worker-Signale entgegen und ruft die Callbacks im GUI-Thread.

    Ein Fehler in on_success/on_error verhindert nicht die Zustellung von
    on_done — das done-Ereignis ist separat queued und der done-Slot gibt in
    jedem Fall die Referenzen frei.
    """

    def __init__(
        self,
        task: Task,
        on_success: Callable[[Any], None] | None,
        on_error: Callable[[str, str], None] | None,
        on_done: Callable[[], None] | None,
    ) -> None:
        super().__init__()
        self._task = task
        self._on_success = on_success
        self._on_error = on_error
        self._on_done = on_done
        task.signals.finished.connect(self._success)
        task.signals.failed.connect(self._error)
        task.signals.done.connect(self._done)

    @Slot(object)
    def _success(self, result: Any) -> None:
        if self._on_success:
            self._on_success(result)

    @Slot(str, str)
    def _error(self, message: str, details: str) -> None:
        if self._on_error:
            self._on_error(message, details)

    @Slot()
    def _done(self) -> None:
        try:
            if self._on_done:
                self._on_done()
        finally:
            self._task = None
            _ACTIVE.discard(self)


def run_task(
    func: Callable[..., Any],
    *args: Any,
    on_success: Callable[[Any], None] | None = None,
    on_error: Callable[[str, str], None] | None = None,
    on_done: Callable[[], None] | None = None,
    **kwargs: Any,
) -> Task:
    task = Task(func, *args, **kwargs)
    bridge = _Bridge(task, on_success, on_error, on_done)
    _ACTIVE.add(bridge)
    QThreadPool.globalInstance().start(task)
    return task
