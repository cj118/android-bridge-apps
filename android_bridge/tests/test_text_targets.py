"""Focused text-field selection for typing approvals (0.3.23).

These are pure-function tests: no server, no ADB, no approval store. They pin
the rules that decide whether typing is allowed to be proposed at all.
"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.join(os.path.dirname(HERE), "app")
sys.path.insert(0, APP_DIR)

import control as control_actions  # noqa: E402


def dump(node):
    return (
        "<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>\n"
        '<hierarchy rotation="0">'
        '<node index="0" text="" resource-id="" '
        'class="android.widget.FrameLayout" bounds="[0,0][1920,1200]" '
        'clickable="false" visible-to-user="true">'
        "%s</node></hierarchy>" % node
    )


def field(**overrides):
    attributes = {
        "index": "0",
        "text": "",
        "resource-id": "com.android.settings:id/search_src_text",
        "class": "android.widget.EditText",
        "bounds": "[400,700][1500,860]",
        "focused": "true",
        "clickable": "true",
        "visible-to-user": "true",
    }
    attributes.update(overrides)
    return "<node %s />" % " ".join(
        '%s="%s"' % (key, value) for key, value in attributes.items()
    )


class FocusedTextTests(unittest.TestCase):
    def test_identifies_the_focused_editable_field(self):
        result = control_actions.focused_text_field(dump(field()))
        self.assertTrue(result["identified"])
        self.assertEqual(result["bounds"], [400, 700, 1500, 860])
        self.assertEqual(
            result["description"],
            'text field "com.android.settings:id/search_src_text" '
            "at [400,700][1500,860]",
        )

    def test_field_contents_are_never_the_label(self):
        result = control_actions.focused_text_field(
            dump(field(text="my home address"))
        )
        self.assertNotIn("my home address", str(result))

    def test_content_description_is_preferred_for_a_readable_name(self):
        result = control_actions.focused_text_field(
            dump(field(**{"content-desc": "Search"}))
        )
        self.assertIn('"Search"', result["description"])

    def test_unfocused_field_is_refused(self):
        result = control_actions.focused_text_field(
            dump(field(focused="false"))
        )
        self.assertFalse(result["identified"])
        self.assertEqual(result["reason"], "no_focused_text_field")

    def test_hidden_field_is_refused(self):
        result = control_actions.focused_text_field(
            dump(field(**{"visible-to-user": "false"}))
        )
        self.assertFalse(result["identified"])
        self.assertEqual(result["reason"], "no_focused_text_field")

    def test_two_focused_fields_are_ambiguous(self):
        result = control_actions.focused_text_field(
            dump(
                field(**{"resource-id": "com.x:id/one"})
                + field(**{"resource-id": "com.x:id/two",
                           "bounds": "[1000,700][1500,860]"})
            )
        )
        self.assertFalse(result["identified"])
        self.assertEqual(result["reason"], "ambiguous_text_field")

    def test_non_editable_focus_is_refused(self):
        result = control_actions.focused_text_field(
            dump(field(**{"class": "android.widget.Button"}))
        )
        self.assertFalse(result["identified"])
        self.assertEqual(result["reason"], "no_focused_text_field")

    def test_password_attribute_is_refused(self):
        result = control_actions.focused_text_field(
            dump(field(password="true", text="hunter2"))
        )
        self.assertFalse(result["identified"])
        self.assertEqual(result["reason"], "sensitive_field_refused")
        self.assertTrue(result["sensitive"])
        self.assertNotIn("hunter2", str(result))

    def test_password_class_is_refused(self):
        result = control_actions.focused_text_field(
            dump(field(**{"class": "android.widget.PasswordEditText"}))
        )
        self.assertEqual(result["reason"], "sensitive_field_refused")

    def test_secret_field_names_are_refused(self):
        for identifier in (
            "com.android.settings:id/pin_entry",
            "com.android.settings:id/otp",
            "com.android.settings:id/cvv",
            "com.android.settings:id/card_number",
            "com.android.settings:id/account_number",
            "com.x:id/api_key",
            "com.x:id/password",
            "com.x:id/one_time_code",
        ):
            with self.subTest(identifier=identifier):
                result = control_actions.focused_text_field(
                    dump(field(**{"resource-id": identifier}))
                )
                self.assertEqual(
                    result["reason"], "sensitive_field_refused"
                )

    def test_ordinary_names_are_not_mistaken_for_secrets(self):
        for identifier in (
            "com.android.settings:id/search_src_text",
            "com.x:id/spinner",
            "com.x:id/shipping_address",
            "com.x:id/passenger_name",
        ):
            with self.subTest(identifier=identifier):
                result = control_actions.focused_text_field(
                    dump(field(**{"resource-id": identifier}))
                )
                self.assertTrue(result["identified"], result)

    def test_unreadable_dump_fails_closed(self):
        for xml in ("", "<hierarchy>", b"not xml"):
            with self.subTest(xml=xml):
                result = control_actions.focused_text_field(xml)
                self.assertFalse(result["identified"])
                self.assertEqual(result["reason"], "target_unverified")

    def test_unlabelled_field_still_has_bounds(self):
        result = control_actions.focused_text_field(
            dump(field(**{"resource-id": ""}))
        )
        self.assertTrue(result["identified"])
        self.assertEqual(
            result["description"], "focused text field at [400,700][1500,860]"
        )


class TextTargetMatchTests(unittest.TestCase):
    def proposal(self):
        return control_actions.focused_text_field(dump(field()))

    def test_unchanged_field_matches(self):
        self.assertTrue(
            control_actions.text_targets_match(
                self.proposal(), self.proposal()
            )
        )

    def test_moved_or_resized_field_does_not_match(self):
        moved = control_actions.focused_text_field(
            dump(field(bounds="[400,720][1500,880]"))
        )
        self.assertFalse(
            control_actions.text_targets_match(self.proposal(), moved)
        )

    def test_relabelled_field_does_not_match(self):
        renamed = control_actions.focused_text_field(
            dump(field(**{"resource-id": "com.x:id/other"}))
        )
        self.assertFalse(
            control_actions.text_targets_match(self.proposal(), renamed)
        )

    def test_unidentified_field_never_matches(self):
        missing = control_actions.focused_text_field(dump(""))
        self.assertFalse(
            control_actions.text_targets_match(self.proposal(), missing)
        )
        self.assertFalse(
            control_actions.text_targets_match(missing, self.proposal())
        )

    def test_malformed_records_never_match(self):
        self.assertFalse(control_actions.text_targets_match(None, None))
        self.assertFalse(
            control_actions.text_targets_match({}, self.proposal())
        )


class TextInputShapeTests(unittest.TestCase):
    def action(self, text):
        return control_actions.validate_text(
            text, "type a phrase", "needed to check the search box"
        )

    def test_spaces_become_percent_s_and_text_is_one_argument(self):
        args = control_actions.adb_args(self.action("hello world"), "SERIAL")
        self.assertEqual(
            args,
            ["-s", "SERIAL", "shell", "input", "text", "hello%sworld"],
        )

    def test_tampered_text_is_refused_before_adb(self):
        action = self.action("hello world")
        for tampered in (
            "hello; rm -rf /",
            "hello world\n",
            "$(id)",
            "a|b",
            "x" * 201,
            "",
        ):
            with self.subTest(tampered=tampered[:20]):
                action["text"] = tampered
                with self.assertRaises(control_actions.ActionError):
                    control_actions.adb_args(action, "SERIAL")

    def test_describe_does_not_echo_the_text(self):
        described = control_actions.describe(self.action("hello world"))
        self.assertNotIn("hello", described)
        self.assertEqual(described, "Type 11 characters")

    def test_purpose_and_reason_are_required_when_supplied(self):
        for purpose, reason in (("", "ok"), ("ok", "")):
            with self.subTest(purpose=purpose, reason=reason):
                with self.assertRaises(control_actions.ActionError):
                    control_actions.validate_text(
                        "hello", purpose, reason
                    )

    def test_plain_validation_still_works_without_purpose(self):
        self.assertEqual(
            control_actions.validate_text("hello")["type"], "text"
        )


if __name__ == "__main__":
    unittest.main()
