# -*- coding: utf8 -*-
# ============LICENSE_START====================================================
# org.onap.vvp/validation-scripts
# ===================================================================
# Copyright © 2019 AT&T Intellectual Property. All rights reserved.
# ===================================================================
#
# Unless otherwise specified, all software contained herein is licensed
# under the Apache License, Version 2.0 (the "License");
# you may not use this software except in compliance with the License.
# You may obtain a copy of the License at
#
#             http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
#
# Unless otherwise specified, all documentation contained herein is licensed
# under the Creative Commons License, Attribution 4.0 Intl. (the "License");
# you may not use this documentation except in compliance with the License.
# You may obtain a copy of the License at
#
#             https://creativecommons.org/licenses/by/4.0/
#
# Unless required by applicable law or agreed to in writing, documentation
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# ============LICENSE_END============================================
#
#

"""
A GUI that wraps the pytest validations scripts.

To make an executable for windows execute  the ``make_exe.bat`` to generate the
.exe and its associated files.  The the necessary files will be written to the
``dist/vvp/`` directory.  This entire directory must be copied to the target machine.

NOTE: This script does require Python 3.6+
"""

import os
import traceback

import pytest
import yaml
import version
import contextlib
import multiprocessing
import queue
import tempfile
import webbrowser
import zipfile
import platform
import subprocess  # nosec

from multiprocessing import Queue
from pathlib import Path
from shutil import rmtree
from tkinter import (
    Radiobutton,
    filedialog,
    font,
    messagebox,
    Tk,
    PanedWindow,
    BOTH,
    HORIZONTAL,
    RAISED,
    Frame,
    Label,
    W,
    StringVar,
    OptionMenu,
    LabelFrame,
    E,
    BooleanVar,
    Entry,
    Button,
    WORD,
    END,
    Checkbutton,
    IntVar,
    Toplevel,
    Message,
    CURRENT,
    Text,
    INSERT,
    DISABLED,
    FLAT,
    CENTER,
    ACTIVE,
    LEFT,
    Menu,
    NORMAL,
)
from tkinter.scrolledtext import ScrolledText
from typing import Optional, TextIO, Callable

from config import Config
from preload.engine import PLUGIN_MGR

VERSION = version.VERSION
PATH = os.path.dirname(os.path.realpath(__file__))
OUT_DIR = "output"


class ToolTip(object):
    """
    create a tooltip for a given widget
    """

    def __init__(self, widget, text="widget info"):
        self.waittime = 750  # milliseconds
        self.wraplength = 300  # pixels
        self.widget = widget
        self.text = text
        self.widget.bind("<Enter>", self.enter)
        self.widget.bind("<Leave>", self.leave)
        self.widget.bind("<ButtonPress>", self.leave)
        self.id = None
        self.tw = None

    # noinspection PyUnusedLocal
    def enter(self, event=None):
        self.schedule()

    # noinspection PyUnusedLocal
    def leave(self, event=None):
        self.unschedule()
        self.hidetip()

    def schedule(self):
        self.unschedule()
        self.id = self.widget.after(self.waittime, self.showtip)

    def unschedule(self):
        orig_id = self.id
        self.id = None
        if orig_id:
            self.widget.after_cancel(orig_id)

    # noinspection PyUnusedLocal
    def showtip(self, event=None):
        x = y = 0
        x, y, cx, cy = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 20
        # creates a top level window
        self.tw = Toplevel(self.widget)
        # Leaves only the label and removes the app window
        self.tw.wm_overrideredirect(True)
        self.tw.wm_geometry("+%d+%d" % (x, y))
        label = Label(
            self.tw,
            text=self.text,
            justify="left",
            background="#ffffff",
            relief="solid",
            borderwidth=1,
            wraplength=self.wraplength,
        )
        label.pack(ipadx=1)

    def hidetip(self):
        tw = self.tw
        self.tw = None
        if tw:
            tw.destroy()


class HyperlinkManager:
    """Adapted from http://effbot.org/zone/tkinter-text-hyperlink.htm"""

    def __init__(self, text):
        self.links = {}
        self.text = text
        self.text.tag_config("hyper", foreground="blue", underline=1)
        self.text.tag_bind("hyper", "<Enter>", self._enter)
        self.text.tag_bind("hyper", "<Leave>", self._leave)
        self.text.tag_bind("hyper", "<Button-1>", self._click)
        self.reset()

    def reset(self):
        self.links.clear()

    def add(self, action):
        # add an action to the manager.  returns tags to use in
        # associated text widget
        tag = "hyper-%d" % len(self.links)
        self.links[tag] = action
        return "hyper", tag

    # noinspection PyUnusedLocal
    def _enter(self, event):
        self.text.config(cursor="hand2")

    # noinspection PyUnusedLocal
    def _leave(self, event):
        self.text.config(cursor="")

    # noinspection PyUnusedLocal
    def _click(self, event):
        for tag in self.text.tag_names(CURRENT):
            if tag[:6] == "hyper-":
                self.links[tag]()
                return


def run_pytest(
    template_dir: str,
    log: TextIO,
    result_queue: Queue,
    categories: Optional[list],
    report_format: str,
    halt_on_failure: bool,
    template_source: str,
    preload_config: str,
    preload_format: list,
    preload_source: str,
    console_tb: bool,
):
    """Runs pytest using the given ``profile`` in a background process.  All
    ``stdout`` and ``stderr`` are redirected to ``log``.  The result of the job
    will be put on the ``completion_queue``

    :param template_dir:        The directory containing the files to be validated.
    :param log: `               `stderr`` and ``stdout`` of the pytest job will be
                                directed here
    :param result_queue:        Completion status posted here.  See :class:`Config`
                                for more information.
    :param categories:          list of optional categories. When provided, pytest
                                will collect and execute all tests that are
                                decorated with any of the passed categories, as
                                well as tests not decorated with a category.
    :param report_format:       Determines the style of report written.  Options are
                                csv, html, or excel
    :param halt_on_failure:     Determines if validation will halt when basic failures
                                are encountered in the input files.  This can help
                                prevent a large number of errors from flooding the
                                report.
    :param template_source:     The path or name of the template to show on the report
    :param preload_config:      Optional directory or file that is input to preload
                                data source
    :param preload_format:      Selected preload format
    :param preload_source:      Name of selected preload data source plugin
    :param console_tb:          Enable or disable traceback on failures
    """
    out_path = "{}/{}".format(PATH, OUT_DIR)
    if os.path.exists(out_path):
        rmtree(out_path, ignore_errors=True)
    with contextlib.redirect_stderr(log), contextlib.redirect_stdout(log):
        try:
            args = [
                "tests",
                "--capture=sys",
                "--template-directory={}".format(template_dir),
                "--report-format={}".format(report_format),
                "--template-source={}".format(template_source),
            ]
            if preload_config:
                args.append("--preload-source={}".format(preload_config))
                args.append(
                    "--preload-source-type={}".format(
                        PLUGIN_MGR.get_source_for_name(preload_source).get_identifier()
                    )
                )
            if categories:
                for category in categories:
                    args.extend(("--category", category))
            if not halt_on_failure:
                args.append("--continue-on-failure")
            if not console_tb:
                args.append("--tb=no")
            if preload_format:
                args.append("--preload-format={}".format(preload_format))
            print("args: ", " ".join(args))
            pytest.main(args=args)
            result_queue.put((True, None))
        except Exception:
            result_queue.put((False, traceback.format_exc()))


def run_pytest_cnf(
    template_dir: str,
    log: TextIO,
    result_queue: Queue,
    report_format: str,
    template_source: str,
    console_tb: bool,
):
    """Runs pytest using the given ``profile`` in a background process.  All
    ``stdout`` and ``stderr`` are redirected to ``log``.  The result of the job
    will be put on the ``completion_queue``

    :param template_dir:        The directory containing the files to be validated.
    :param log: `               `stderr`` and ``stdout`` of the pytest job will be
                                directed here
    :param result_queue:        Completion status posted here.  See :class:`Config`
                                for more information.
    :param report_format:       Determines the style of report written.  Options are
                                csv, html, or excel
    :param template_source:     The path or name of the template to show on the report
    :param console_tb:          Enable or disable traceback on failures
    """
    out_path = "{}/{}".format(PATH, OUT_DIR)
    if os.path.exists(out_path):
        rmtree(out_path, ignore_errors=True)
    with contextlib.redirect_stderr(log), contextlib.redirect_stdout(log):
        try:
            args = [
                "tests_cnf",
                "--capture=sys",
                "--package-directory={}".format(template_dir),
                "--report-format={}".format(report_format),
                "--package-source={}".format(template_source),
            ]
            if not console_tb:
                args.append("--tb=no")
            print("args: ", " ".join(args))
            pytest.main(args=args)
            result_queue.put((True, None))
        except Exception:
            result_queue.put((False, traceback.format_exc()))


class Dialog(Toplevel):
    """
    Adapted from http://www.effbot.org/tkinterbook/tkinter-dialog-windows.htm
    """

    def __init__(self, parent: Frame, title=None):
        Toplevel.__init__(self, parent)
        self.transient(parent)
        if title:
            self.title(title)
        self.parent = parent
        self.result = None
        body = Frame(self)
        self.initial_focus = self.body(body)
        body.pack(padx=5, pady=5)
        self.buttonbox()
        self.grab_set()
        if not self.initial_focus:
            self.initial_focus = self
        self.protocol("WM_DELETE_WINDOW", self.cancel)
        self.geometry(
            "+%d+%d" % (parent.winfo_rootx() + 600, parent.winfo_rooty() + 400)
        )
        self.initial_focus.focus_set()
        self.wait_window(self)

    def body(self, master):
        raise NotImplementedError()

    # noinspection PyAttributeOutsideInit
    def buttonbox(self):
        box = Frame(self)
        self.accept = Button(
            box,
            text="Accept",
            width=10,
            state=DISABLED,
            command=self.ok,
            default=ACTIVE,
        )
        self.accept.pack(side=LEFT, padx=5, pady=5)
        self.decline = Button(
            box, text="Decline", width=10, state=DISABLED, command=self.cancel
        )
        self.decline.pack(side=LEFT, padx=5, pady=5)
        self.bind("<Return>", self.ok)
        self.bind("<Escape>", self.cancel)
        box.pack()

    # noinspection PyUnusedLocal
    def ok(self, event=None):
        self.withdraw()
        self.update_idletasks()
        self.apply()
        self.cancel()

    # noinspection PyUnusedLocal
    def cancel(self, event=None):
        self.parent.focus_set()
        self.destroy()

    def apply(self):
        raise NotImplementedError()

    def activate_buttons(self):
        self.accept.configure(state=NORMAL)
        self.decline.configure(state=NORMAL)


class TermsAndConditionsDialog(Dialog):
    def __init__(self, parent, config: Config):
        self.config = config
        self.parent = parent
        super().__init__(parent, config.terms_popup_title)

    def body(self, master):
        Label(master, text=self.config.terms_popup_message).grid(row=0, pady=5)
        tc_link = Label(
            master, text=self.config.terms_link_text, fg="blue", cursor="hand2"
        )
        ValidatorApp.underline(tc_link)
        tc_link.bind("<Button-1>", self.open_terms)
        tc_link.grid(row=1, pady=5)

    # noinspection PyUnusedLocal
    def open_terms(self, event):
        webbrowser.open(self.config.terms_link_url)
        self.activate_buttons()

    def apply(self):
        self.config.set_terms_accepted()


class ValidatorApp:
    def __init__(self, config: Config = None):
        """Constructs the GUI element of the Validation Tool"""
        self.task = None
        self.config = config or Config()

        self._root = Tk()
        self._root.title(self.config.app_name)
        self._root.protocol("WM_DELETE_WINDOW", self.shutdown)

        if self.config.terms_link_text:
            menubar = Menu(self._root)
            menubar.add_command(
                label=self.config.terms_link_text,
                command=lambda: webbrowser.open(self.config.terms_link_url),
            )
            self._root.config(menu=menubar)

        parent_frame = Frame(self._root)
        main_window = PanedWindow(parent_frame)
        main_window.pack(fill=BOTH, expand=1)

        control_panel = PanedWindow(
            main_window, orient=HORIZONTAL, sashpad=4, sashrelief=RAISED
        )
        actions = Frame(control_panel)
        control_panel.add(actions)
        control_panel.paneconfigure(actions, minsize=350)

        if self.config.disclaimer_text or self.config.requirement_link_text:
            self.footer = self.create_footer(parent_frame)
        parent_frame.pack(fill=BOTH, expand=True)

        self.nf_type = StringVar(self._root, name="nf_type_var")
        self.nf_type.set(self.config.default_nf_type_var)

        def update_nf_type():
            if self.nf_type.get() == "CNF":
                category_frame.grid_remove()
                preload_format_label.grid_remove()
                preload_format_menu.grid_remove()
                preload_source_label.grid_remove()
                preload_source_menu.grid_remove()
                halt_on_failure_label.grid_remove()
                halt_checkbox.grid_remove()
                create_preloads_label.grid_remove()
                create_preloads_checkbox.grid_remove()
                preload_config_label.grid_remove()
                self.preload_config_entry.grid_remove()
                preload_config_browse.grid_remove()

                additional_tests_frame.grid()

                self.validate_button_text.set("Process Package")

            if self.nf_type.get() == "VNF":
                category_frame.grid()
                preload_format_label.grid()
                preload_format_menu.grid()
                preload_source_label.grid()
                preload_source_menu.grid()
                halt_on_failure_label.grid()
                halt_checkbox.grid()
                create_preloads_label.grid()
                create_preloads_checkbox.grid()
                preload_config_label.grid()
                self.preload_config_entry.grid()
                preload_config_browse.grid()

                additional_tests_frame.grid_remove()

                self.validate_button_text.set("Process Templates")

        # profile start
        nf_select_frame = LabelFrame(actions, text="Network Function Type")
        nf_select_frame.grid(row=1, column=1, columnspan=3, pady=10, sticky="we")
        VNF_radiobutton = Radiobutton(
            nf_select_frame, variable=self.nf_type, value="VNF", command=update_nf_type
        )
        VNF_radiobutton.grid(row=1, column=1, sticky=W, padx=(50, 1))
        VNF_label = Label(nf_select_frame, text="VNF")
        VNF_label.grid(row=1, column=2, sticky=W)
        CNF_radiobutton = Radiobutton(
            nf_select_frame, variable=self.nf_type, value="CNF", command=update_nf_type
        )
        CNF_radiobutton.grid(row=1, column=3, sticky=W, padx=(50, 1))
        CNF_label = Label(nf_select_frame, text="CNF")
        CNF_label.grid(row=1, column=4, sticky=W)

        number_of_categories = len(self.config.category_names)
        category_frame = LabelFrame(actions, text="Additional Validation Categories:")
        category_frame.grid(row=2, column=1, columnspan=3, pady=5, sticky="we")

        self.categories = []

        for x in range(0, number_of_categories):
            category_name = self.config.category_names[x]
            category_value = IntVar(value=0)
            category_value._name = "category_{}".format(category_name.replace(" ", "_"))
            # noinspection PyProtectedMember
            category_value.set(self.config.get_category_value(category_value._name))
            self.categories.append(category_value)
            category_checkbox = Checkbutton(
                category_frame, text=category_name, variable=self.categories[x]
            )
            ToolTip(category_checkbox, self.config.get_description(category_name))
            category_checkbox.grid(row=x + 1, column=1, columnspan=2, sticky="w")

        settings_frame = LabelFrame(actions, text="Settings")
        settings_row = 1
        settings_frame.grid(row=3, column=1, columnspan=3, pady=10, sticky="we")

        if self.config.preload_formats:
            preload_format_label = Label(settings_frame, text="Preload Format:")
            preload_format_label.grid(row=settings_row, column=1, sticky=W)
            self.preload_format = StringVar(self._root, name="preload_format")
            self.preload_format.set(self.config.default_preload_format)
            preload_format_menu = OptionMenu(
                settings_frame, self.preload_format, *self.config.preload_formats
            )
            preload_format_menu.config(width=25)
            preload_format_menu.grid(
                row=settings_row, column=2, columnspan=3, sticky=E, pady=5
            )
            settings_row += 1

            preload_source_label = Label(settings_frame, text="Preload Source:")
            preload_source_label.grid(row=settings_row, column=1, sticky=W)
            self.preload_source = StringVar(self._root, name="preload_source")
            self.preload_source.set(self.config.default_preload_source)
            preload_source_menu = OptionMenu(
                settings_frame, self.preload_source, *self.config.preload_source_types
            )
            preload_source_menu.config(width=25)
            preload_source_menu.grid(
                row=settings_row, column=2, columnspan=3, sticky=E, pady=5
            )
            settings_row += 1

        report_format_label = Label(settings_frame, text="Report Format:")
        report_format_label.grid(row=settings_row, column=1, sticky=W)
        self.report_format = StringVar(self._root, name="report_format")
        self.report_format.set(self.config.default_report_format)
        report_format_menu = OptionMenu(
            settings_frame, self.report_format, *self.config.report_formats
        )
        report_format_menu.config(width=25)
        report_format_menu.grid(
            row=settings_row, column=2, columnspan=3, sticky=E, pady=5
        )
        settings_row += 1

        input_format_label = Label(settings_frame, text="Input Format:")
        input_format_label.grid(row=settings_row, column=1, sticky=W)
        self.input_format = StringVar(self._root, name="input_format")
        self.input_format.set(self.config.default_input_format)
        input_format_menu = OptionMenu(
            settings_frame, self.input_format, *self.config.input_formats
        )
        input_format_menu.config(width=25)
        input_format_menu.grid(
            row=settings_row, column=2, columnspan=3, sticky=E, pady=5
        )
        settings_row += 1

        additional_tests_frame = Frame(settings_frame)
        additional_tests_row = 1
        additional_tests_label = Label(
            additional_tests_frame, text="Additional Tests:", anchor=W, justify=LEFT
        )
        additional_tests_label.grid(
            row=additional_tests_row, column=1, sticky=W, pady=5
        )
        additional_tests_row += 1

        number_of_additional_cnf_tests = len(self.config.additional_cnf_tests)
        self.additional_cnf_tests = []

        for x in range(0, number_of_additional_cnf_tests):
            test = self.config.additional_cnf_tests[x]
            test_value = BooleanVar(self._root, name=test["test"])
            test_value.set(self.config.get_additional_cnf_test_value(test_value._name))
            self.additional_cnf_tests.append(test_value)
            test_label = Label(
                additional_tests_frame, text=test["name"], anchor=W, justify=LEFT
            )
            test_label.grid(row=x + 2, column=2, sticky=W, pady=5)
            test_checkbox = Checkbutton(
                additional_tests_frame,
                offvalue=False,
                onvalue=True,
                variable=self.additional_cnf_tests[x],
            )
            test_checkbox.grid(row=x + 2, column=3, columnspan=2, sticky=W, pady=5)

        additional_tests_frame.grid(
            row=settings_row, column=1, columnspan=3, sticky=W, pady=5
        )
        settings_row += 1

        console_tb_frame = Frame(settings_frame)
        self.console_tb = BooleanVar(self._root, name="console_tb")
        self.console_tb.set(self.config.default_console_tb)
        console_tb_label = Label(
            console_tb_frame, text="Console output:", anchor=W, justify=LEFT
        )
        console_tb_label.grid(row=settings_row, column=1, sticky=W, pady=5)
        tb_enable_radiobutton = Radiobutton(
            console_tb_frame, variable=self.console_tb, value=True
        )
        tb_enable_radiobutton.grid(row=settings_row, column=2, sticky=W)
        tb_enable_label = Label(console_tb_frame, text="Detailed")
        tb_enable_label.grid(row=settings_row, column=3, sticky=W)
        tb_disable_radiobutton = Radiobutton(
            console_tb_frame, variable=self.console_tb, value=False
        )
        tb_disable_radiobutton.grid(row=settings_row, column=4, sticky=W)
        tb_disable_label = Label(console_tb_frame, text="Simple")
        tb_disable_label.grid(row=settings_row, column=5, sticky=W)

        console_tb_frame.grid(
            row=settings_row, column=1, columnspan=3, sticky=W, pady=5
        )
        settings_row += 1

        self.halt_on_failure = BooleanVar(self._root, name="halt_on_failure")
        self.halt_on_failure.set(self.config.default_halt_on_failure)
        halt_on_failure_label = Label(
            settings_frame, text="Halt on Basic Failures:", anchor=W, justify=LEFT
        )
        halt_on_failure_label.grid(row=settings_row, column=1, sticky=W, pady=5)
        halt_checkbox = Checkbutton(
            settings_frame, offvalue=False, onvalue=True, variable=self.halt_on_failure
        )
        halt_checkbox.grid(row=settings_row, column=2, columnspan=2, sticky=W, pady=5)
        settings_row += 1

        self.create_preloads = BooleanVar(self._root, name="create_preloads")
        self.create_preloads.set(self.config.default_create_preloads)
        create_preloads_label = Label(
            settings_frame,
            text="Create Preload from Datasource:",
            anchor=W,
            justify=LEFT,
        )
        create_preloads_label.grid(row=settings_row, column=1, sticky=W, pady=5)
        create_preloads_checkbox = Checkbutton(
            settings_frame,
            offvalue=False,
            onvalue=True,
            variable=self.create_preloads,
            command=self.set_env_dir_state,
        )
        create_preloads_checkbox.grid(
            row=settings_row, column=2, columnspan=2, sticky=W, pady=5
        )

        directory_label = Label(actions, text="Template Location:")
        directory_label.grid(row=4, column=1, pady=5, sticky=W)
        self.template_source = StringVar(self._root, name="template_source")
        directory_entry = Entry(actions, width=40, textvariable=self.template_source)
        directory_entry.grid(row=4, column=2, pady=5, sticky=W)
        directory_browse = Button(actions, text="...", command=self.ask_template_source)
        directory_browse.grid(row=4, column=3, pady=5, sticky=W)

        preload_config_label = Label(actions, text="Preload Datasource:")
        preload_config_label.grid(row=5, column=1, pady=5, sticky=W)
        self.preload_config = StringVar(self._root, name="preload_config")
        preload_config_state = NORMAL if self.create_preloads.get() else DISABLED
        self.preload_config_entry = Entry(
            actions,
            width=40,
            textvariable=self.preload_config,
            state=preload_config_state,
        )
        self.preload_config_entry.grid(row=5, column=2, pady=5, sticky=W)
        preload_config_browse = Button(
            actions, text="...", command=self.ask_preload_source
        )
        preload_config_browse.grid(row=5, column=3, pady=5, sticky=W)

        self.validate_button_text = StringVar()
        self.validate_button_text.set("Process Templates")

        validate_button = Button(
            actions, textvariable=self.validate_button_text, command=self.validate
        )
        validate_button.grid(row=6, column=1, columnspan=2, pady=5)

        self.result_panel = Frame(actions)
        # We'll add these labels now, and then make them visible when the run completes
        self.completion_label = Label(self.result_panel, text="Validation Complete!")
        self.result_label = Label(
            self.result_panel, text="View Report", fg="blue", cursor="hand2"
        )
        self.underline(self.result_label)
        self.result_label.bind("<Button-1>", self.open_report)

        self.preload_label = Label(
            self.result_panel, text="View Preload Templates", fg="blue", cursor="hand2"
        )
        self.underline(self.preload_label)
        self.preload_label.bind("<Button-1>", self.open_preloads)

        self.result_panel.grid(row=7, column=1, columnspan=2)
        control_panel.pack(fill=BOTH, expand=1)

        main_window.add(control_panel)

        self.log_panel = ScrolledText(main_window, wrap=WORD, width=120, height=20)
        self.log_panel.configure(font=font.Font(family="Courier New", size="11"))
        self.log_panel.pack(fill=BOTH, expand=1)

        main_window.add(self.log_panel)

        # Briefly add the completion and result labels so the window size includes
        # room for them
        self.completion_label.pack()
        self.result_label.pack()  # Show report link
        self.preload_label.pack()  # Show preload link
        self._root.after_idle(
            lambda: (
                self.completion_label.pack_forget(),
                self.result_label.pack_forget(),
                self.preload_label.pack_forget(),
                update_nf_type(),
            )
        )

        self.config.watch(
            *self.categories,
            self.input_format,
            self.report_format,
            self.halt_on_failure,
            self.preload_format,
            self.create_preloads,
            self.preload_source,
            *self.additional_cnf_tests,
            self.nf_type,
            self.console_tb
        )
        self.schedule(self.execute_pollers)
        if self.config.terms_link_text and not self.config.are_terms_accepted:
            TermsAndConditionsDialog(parent_frame, self.config)
            if not self.config.are_terms_accepted:
                self.shutdown()

    def create_footer(self, parent_frame):
        footer = Frame(parent_frame)
        disclaimer = Message(footer, text=self.config.disclaimer_text, anchor=CENTER)
        disclaimer.grid(row=0, pady=2)
        parent_frame.bind(
            "<Configure>", lambda e: disclaimer.configure(width=e.width - 20)
        )
        if self.config.requirement_link_text:
            requirement_link = Text(
                footer,
                height=1,
                bg=disclaimer.cget("bg"),
                relief=FLAT,
                font=disclaimer.cget("font"),
            )
            requirement_link.tag_configure("center", justify="center")
            hyperlinks = HyperlinkManager(requirement_link)
            requirement_link.insert(INSERT, "Validating: ")
            requirement_link.insert(
                INSERT,
                self.config.requirement_link_text,
                hyperlinks.add(self.open_requirements),
            )
            requirement_link.tag_add("center", "1.0", "end")
            requirement_link.config(state=DISABLED)
            requirement_link.grid(row=1, pady=2)
            ToolTip(requirement_link, self.config.requirement_link_url)
        footer.grid_columnconfigure(0, weight=1)
        footer.pack(fill=BOTH, expand=True)
        return footer

    def set_env_dir_state(self):
        state = NORMAL if self.create_preloads.get() else DISABLED
        if state == DISABLED:
            self.preload_config.set("")
        self.preload_config_entry.config(state=state)

    def ask_template_source(self):
        if self.input_format.get() == "ZIP File":
            template_source = filedialog.askopenfilename(
                title="Select Archive",
                filetypes=(("ZIP Files", "*.zip"), ("All Files", "*")),
            )
        else:
            template_source = filedialog.askdirectory()
        self.template_source.set(template_source)

    def ask_preload_source(self):
        input_type = "DIR"
        for source in PLUGIN_MGR.preload_sources:
            if source.get_name() == self.preload_source.get():
                input_type = source.get_source_type()

        if input_type == "DIR":
            self.preload_config.set(filedialog.askdirectory())
        else:
            self.preload_config.set(
                filedialog.askopenfilename(
                    title="Select Preload Datasource File",
                    filetypes=(("All Files", "*"),),
                )
            )

    def validate(self):
        """Run the pytest validations in a background process"""
        if not self.delete_prior_report():
            return

        if not self.template_source.get():
            self.ask_template_source()

        template_dir = self.resolve_template_dir()

        optional_cnf_tests_settings = {}

        if template_dir:
            self.kill_background_task()
            self.clear_log()
            self.completion_label.pack_forget()
            self.result_label.pack_forget()
            self.preload_label.pack_forget()
            # if self.nf_type == "VNF":
            self.task = (
                multiprocessing.Process(
                    target=run_pytest,
                    args=(
                        template_dir,
                        self.config.log_file,
                        self.config.status_queue,
                        self.categories_list(),
                        self.report_format.get().lower(),
                        self.halt_on_failure.get(),
                        self.template_source.get(),
                        self.preload_config.get(),
                        self.preload_format.get(),
                        self.preload_source.get(),
                        self.console_tb.get(),
                    ),
                )
                if self.nf_type.get() == "VNF"
                else multiprocessing.Process(
                    target=run_pytest_cnf,
                    args=(
                        template_dir,
                        self.config.log_file,
                        self.config.status_queue,
                        self.report_format.get().lower(),
                        self.template_source.get(),
                        self.console_tb.get(),
                    ),
                )
            )
            if self.nf_type.get() == "CNF":
                for x in range(0, len(self.config.additional_cnf_tests)):
                    test = self.config.additional_cnf_tests[x]
                    optional_cnf_tests_settings[
                        test["test"]
                    ] = self.additional_cnf_tests[x].get()
                optional_cnf_tests_settings_file = open(
                    "tests_cnf/optional_tests_setting.yaml", "w"
                )
                yaml.dump(optional_cnf_tests_settings, optional_cnf_tests_settings_file)

            self.task.daemon = True
            self.task.start()

    @property
    def title(self):
        """Returns the text displayed in the title bar of the application"""
        return self._root.title()

    def execute_pollers(self):
        """Call all methods that require periodic execution, and re-schedule
        their execution for the next polling interval"""
        try:
            self.poll_log_file()
            self.poll_status_queue()
            self.poll_command_queue()
        finally:
            self.schedule(self.execute_pollers)

    @staticmethod
    def _drain_queue(q):
        """Yields values from the queue until empty"""
        while True:
            try:
                yield q.get(block=False)
            except queue.Empty:
                break

    def poll_command_queue(self):
        """Picks up command strings from the commmand queue, and
        dispatches it for execution.  Only SHUTDOWN is supported
        currently"""
        for command in self._drain_queue(self.config.command_queue):
            if command == "SHUTDOWN":
                self.shutdown()

    def poll_status_queue(self):
        """Checks for completion of the job, and then displays the View Report link
        if it was successful or writes the exception to the ``log_panel`` if
        it fails."""
        for is_success, e in self._drain_queue(self.config.status_queue):
            if is_success:
                self.completion_label.pack()
                self.result_label.pack()  # Show report link
                if hasattr(self, "preload_format") and self.nf_type.get() == "VNF":
                    self.preload_label.pack()  # Show preload link
            else:
                self.log_panel.insert(END, str(e))

    def poll_log_file(self):
        """Reads captured stdout and stderr from the log queue and writes it to the
        log panel."""
        for line in self._drain_queue(self.config.log_queue):
            self.log_panel.insert(END, line)
            self.log_panel.see(END)

    def schedule(self, func: Callable):
        """Schedule the callable ``func`` to be executed according to
        the polling_frequency"""
        self._root.after(self.config.polling_frequency, func)

    def clear_log(self):
        """Removes all log entries from teh log panel"""
        self.log_panel.delete("1.0", END)

    def delete_prior_report(self) -> bool:
        """Attempts to delete the current report, and pops up a warning message
        to the user if it can't be deleted.  This will force the user to
        close the report before re-running the validation.  Returns True if
        the file was deleted or did not exist, or False otherwise"""
        if not os.path.exists(self.report_file_path):
            return True

        try:
            os.remove(self.report_file_path)
            return True
        except OSError:
            messagebox.showerror(
                "Error",
                "Please close or rename the open report file before re-validating",
            )
            return False

    @property
    def report_file_path(self):
        ext_mapping = {"csv": "csv", "html": "html", "excel": "xlsx"}
        ext = ext_mapping.get(self.report_format.get().lower())
        return os.path.join(PATH, OUT_DIR, "report.{}".format(ext))

    # noinspection PyUnusedLocal
    def open_report(self, event):
        """Open the report in the user's default browser"""
        path = Path(self.report_file_path).absolute().resolve().as_uri()
        webbrowser.open_new(path)

    def open_preloads(self, event):
        """Open the report in the user's default browser"""
        path = os.path.join(
            PATH,
            OUT_DIR,
            "preloads",
            self.config.get_subdir_for_preload(self.preload_format.get()),
        )
        if platform.system() == "Windows":
            os.startfile(path)  # nosec
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", path])  # nosec
        else:
            subprocess.Popen(["xdg-open", path])  # nosec

    def open_requirements(self):
        """Open the report in the user's default browser"""
        webbrowser.open_new(self.config.requirement_link_url)

    def start(self):
        """Start the event loop of the application.  This method does not return"""
        self._root.mainloop()

    @staticmethod
    def underline(label):
        """Apply underline format to an existing label"""
        f = font.Font(label, label.cget("font"))
        f.configure(underline=True)
        label.configure(font=f)

    def kill_background_task(self):
        if self.task and self.task.is_alive():
            self.task.terminate()
            for _ in self._drain_queue(self.config.log_queue):
                pass

    def shutdown(self):
        """Shutdown the application"""
        self.kill_background_task()
        self._root.destroy()

    def check_template_source_is_valid(self):
        """Verifies the value of template source exists and of valid type based
        on input setting"""
        if not self.template_source.get():
            return False
        template_path = Path(self.template_source.get())

        if not template_path.exists():
            messagebox.showerror(
                "Error",
                "Input does not exist. Please provide a valid file or directory.",
            )
            return False

        if self.input_format.get() == "ZIP File":
            if zipfile.is_zipfile(template_path):
                return True
            else:
                messagebox.showerror(
                    "Error", "Expected ZIP file, but input is not a valid ZIP file"
                )
                return False
        else:
            if template_path.is_dir():
                return True
            else:
                messagebox.showerror(
                    "Error", "Expected directory, but input is not a directory"
                )
                return False

    def resolve_template_dir(self) -> str:
        """Extracts the zip file to a temporary directory if needed, otherwise
        returns the directory supplied to template source.  Returns empty string
        if the template source isn't valid"""
        if not self.check_template_source_is_valid():
            return ""
        if self.input_format.get() == "ZIP File":
            temp_dir = tempfile.mkdtemp()
            archive = zipfile.ZipFile(self.template_source.get())
            archive.extractall(path=temp_dir)
            return temp_dir
        else:
            return self.template_source.get()

    def categories_list(self) -> list:
        categories = []
        selected_categories = self.categories
        for x in range(0, len(selected_categories)):
            if selected_categories[x].get():
                category = self.config.category_names[x]
                categories.append(self.config.get_category(category))
        return categories


if __name__ == "__main__":
    multiprocessing.freeze_support()  # needed for PyInstaller to work
    ValidatorApp().start()
