"""Clickable-target descriptions used by tap approvals (0.3.21).

Pure parsing tests: no adb, no server and no device.
"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.join(os.path.dirname(HERE), "app")
sys.path.insert(0, APP_DIR)

import control as control_actions  # noqa: E402

EMPTY = "No clickable element detected — verify visually."
UNKNOWN = "Unknown — could not check."

DUMP = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.widget.FrameLayout"
        package="com.example" bounds="[0,0][1920,1200]"
        clickable="false" visible-to-user="true">
    <node index="0" text="Kitchen" resource-id="com.example:id/kitchen"
          class="android.widget.Button" bounds="[200,600][700,800]"
          clickable="true" visible-to-user="true">
      <node index="0" text="Living Room TV" resource-id="com.example:id/tv_title"
            class="android.widget.TextView" bounds="[450,740][600,780]"
            clickable="false" visible-to-user="true" />
    </node>
    <node index="1" text="" content-desc="Bathroom light"
          resource-id="com.example:id/icon" class="android.widget.ImageButton"
          bounds="[1500,300][1560,360]" clickable="true" visible-to-user="true" />
    <node index="2" text="Hidden label" resource-id="com.example:id/hidden"
          class="android.widget.TextView" bounds="[800,900][1000,1000]"
          clickable="false" visible-to-user="false" />
    <node index="3" text="Hidden press" resource-id="com.example:id/hidden_btn"
          class="android.widget.Button" bounds="[800,1050][1000,1150]"
          clickable="true" visible-to-user="false" />
    <node index="4" text="&amp; &lt;quoted&gt; &quot;x&quot;"
          resource-id="" class="android.widget.Button"
          bounds="[100,1000][400,1100]" clickable="true"
          visible-to-user="true" />
    <node index="5" text="hunter2" resource-id="com.example:id/pass"
          class="android.widget.EditText" password="true"
          bounds="[1100,900][1500,960]" clickable="true"
          visible-to-user="true" />
    <node index="6" text="Panel" resource-id="" class="android.widget.FrameLayout"
          bounds="[1600,700][1900,1000]" clickable="true"
          visible-to-user="true">
      <node index="0" text="Inner" resource-id="" class="android.widget.Button"
            bounds="[1650,750][1710,810]" clickable="true"
            visible-to-user="true" />
    </node>
    <node index="7" text="%s" resource-id="" class="android.widget.Button"
          bounds="[100,1120][400,1160]" clickable="true"
          visible-to-user="true" />
  </node>
</hierarchy>
""" % ("L" * 200)


class DescribeTargetTests(unittest.TestCase):
    def test_clickable_parent_wins_over_smaller_text(self):
        result = control_actions.describe_target(DUMP, 520, 760)
        self.assertTrue(result["identified"])
        self.assertTrue(result["clickable"])
        self.assertEqual(result["label"], "Kitchen")
        self.assertEqual(result["bounds"], [200, 600, 700, 800])
        self.assertEqual(
            result["description"], 'button "Kitchen" at [200,600][700,800]'
        )

    def test_inside_a_clickable_element(self):
        result = control_actions.describe_target(DUMP, 250, 620)
        self.assertEqual(
            result["description"], 'button "Kitchen" at [200,600][700,800]'
        )

    def test_smallest_clickable_nested_element_wins(self):
        result = control_actions.describe_target(DUMP, 1680, 780)
        self.assertEqual(
            result["description"], 'button "Inner" at [1650,750][1710,810]'
        )

    def test_bounds_edges_are_inside(self):
        for x, y in ((200, 600), (700, 800), (200, 800), (700, 600)):
            with self.subTest(x=x, y=y):
                self.assertTrue(
                    control_actions.describe_target(DUMP, x, y)["identified"]
                )

    def test_nothing_clickable_is_not_called_empty(self):
        result = control_actions.describe_target(DUMP, 50, 50)
        self.assertFalse(result["identified"])
        self.assertFalse(result["clickable"])
        self.assertEqual(result["description"], EMPTY)
        self.assertEqual(
            result["description"],
            "No clickable element detected — verify visually.",
        )

    def test_text_without_a_clickable_parent_is_unidentified(self):
        result = control_actions.describe_target(DUMP, 900, 950)
        self.assertEqual(result["description"], EMPTY)

    def test_invisible_elements_are_ignored(self):
        self.assertEqual(
            control_actions.describe_target(DUMP, 900, 950)["description"],
            EMPTY,
        )
        self.assertEqual(
            control_actions.describe_target(DUMP, 900, 1100)["description"],
            EMPTY,
        )

    def test_content_desc_is_used_when_text_is_empty(self):
        result = control_actions.describe_target(DUMP, 1520, 320)
        self.assertEqual(result["label"], "Bathroom light")
        self.assertEqual(
            result["description"],
            'button "Bathroom light" at [1500,300][1560,360]',
        )

    def test_label_keeps_special_characters_for_escaping_at_render(self):
        result = control_actions.describe_target(DUMP, 200, 1050)
        self.assertEqual(result["label"], '& <quoted> "x"')
        self.assertIn('& <quoted> "x"', result["description"])

    def test_password_field_contents_are_never_exposed(self):
        result = control_actions.describe_target(DUMP, 1300, 930)
        self.assertNotIn("hunter2", result["description"])
        self.assertNotIn("hunter2", result["label"])
        self.assertEqual(result["label"], "com.example:id/pass")
        self.assertTrue(result["identified"])

    def test_edit_text_without_password_flag_is_still_protected(self):
        dump = DUMP.replace('password="true"', 'password="false"')
        result = control_actions.describe_target(dump, 1300, 930)
        self.assertNotIn("hunter2", result["description"])

    def test_label_is_truncated_to_eighty_characters(self):
        result = control_actions.describe_target(DUMP, 200, 1140)
        self.assertEqual(len(result["label"]), 80)
        self.assertEqual(len(result["label"]), control_actions.UI_LABEL_MAX)

    def test_label_control_characters_are_collapsed(self):
        dump = DUMP.replace('text="Kitchen"', 'text="Kit&#10;chen&#9;tab"')
        result = control_actions.describe_target(dump, 250, 620)
        self.assertEqual(result["label"], "Kit chen tab")

    def test_malformed_dump_is_unknown(self):
        for xml in ("", "   ", "not xml", "<hierarchy><node bounds='[0,0'", None):
            with self.subTest(xml=xml):
                result = control_actions.describe_target(xml, 10, 10)
                self.assertFalse(result["identified"])
                self.assertEqual(result["description"], UNKNOWN)
                self.assertEqual(
                    result["description"], "Unknown — could not check."
                )

    def test_invalid_bounds_are_ignored(self):
        dump = DUMP.replace(
            'bounds="[200,600][700,800]"', 'bounds="[700,600][200,800]"'
        )
        result = control_actions.describe_target(dump, 250, 620)
        self.assertEqual(result["description"], EMPTY)

    def test_helper_results(self):
        self.assertEqual(control_actions.unknown_target()["description"], UNKNOWN)
        self.assertEqual(
            control_actions.unidentified_target()["description"], EMPTY
        )
        self.assertFalse(control_actions.unknown_target()["identified"])
        self.assertFalse(control_actions.unidentified_target()["identified"])


SECRET_NESTED = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.widget.FrameLayout"
        bounds="[0,0][1920,1200]" clickable="false" visible-to-user="true">
    <node index="0" text="" resource-id="com.example:id/pass"
          class="android.widget.EditText" password="true"
          bounds="[100,100][900,200]" clickable="true"
          visible-to-user="true">
      <node index="0" text="inner-secret" resource-id=""
            class="android.widget.TextView" bounds="[120,120][500,180]"
            clickable="true" visible-to-user="true" />
    </node>
  </node>
</hierarchy>
"""


class SensitiveTextTests(unittest.TestCase):
    def test_nested_value_label_inside_a_field_is_suppressed(self):
        payload = control_actions.list_clickable(SECRET_NESTED)
        self.assertNotIn("inner-secret", str(payload))
        self.assertEqual(
            [element["name"] for element in payload["elements"]],
            ["com.example:id/pass", "unlabelled"],
        )

    def test_described_target_never_contains_nested_value_text(self):
        result = control_actions.describe_target(SECRET_NESTED, 300, 150)
        self.assertNotIn("inner-secret", result["description"])
        self.assertTrue(result["identified"])
        self.assertEqual(
            result["description"], "tappable area at [120,120][500,180]"
        )


class TargetsMatchTests(unittest.TestCase):
    def target(self, label="Kitchen", bounds=(200, 600, 700, 800)):
        return control_actions._target_result(label, bounds)

    def test_unchanged_target_matches(self):
        self.assertTrue(
            control_actions.targets_match(self.target(), self.target())
        )

    def test_changed_bounds_do_not_match(self):
        self.assertFalse(
            control_actions.targets_match(
                self.target(), self.target(bounds=(210, 600, 700, 800))
            )
        )

    def test_changed_label_does_not_match(self):
        self.assertFalse(
            control_actions.targets_match(
                self.target(), self.target(label="Hallway")
            )
        )

    def test_vanished_target_does_not_match(self):
        self.assertFalse(
            control_actions.targets_match(
                self.target(), control_actions.unidentified_target()
            )
        )

    def test_new_clickable_element_does_not_match(self):
        self.assertFalse(
            control_actions.targets_match(
                control_actions.unidentified_target(), self.target()
            )
        )

    def test_inspection_failure_never_matches(self):
        self.assertFalse(
            control_actions.targets_match(
                self.target(), control_actions.unknown_target()
            )
        )
        self.assertFalse(
            control_actions.targets_match(
                control_actions.unknown_target(), self.target()
            )
        )
        self.assertFalse(
            control_actions.targets_match(
                control_actions.unknown_target(),
                control_actions.unknown_target(),
            )
        )

    def test_unidentified_area_is_still_unidentified(self):
        empty = control_actions.unidentified_target()
        self.assertTrue(control_actions.targets_match(empty, empty))

    def test_malformed_records_do_not_match(self):
        self.assertFalse(control_actions.targets_match(None, self.target()))
        self.assertFalse(control_actions.targets_match({}, {}))


class ListClickableTests(unittest.TestCase):
    def test_only_visible_clickable_elements_are_listed(self):
        payload = control_actions.list_clickable(DUMP)
        names = [element["name"] for element in payload["elements"]]
        self.assertEqual(
            names,
            [
                "Kitchen",
                "Bathroom light",
                '& <quoted> "x"',
                "com.example:id/pass",
                "Panel",
                "Inner",
                "L" * 80,
            ],
        )
        self.assertEqual(payload["count"], 7)
        self.assertFalse(payload["truncated"])
        self.assertNotIn("Hidden press", names)

    def test_password_contents_are_never_listed(self):
        payload = control_actions.list_clickable(DUMP)
        rendered = str(payload)
        self.assertNotIn("hunter2", rendered)

    def test_result_is_bounded(self):
        payload = control_actions.list_clickable(DUMP, limit=1)
        self.assertEqual(payload["count"], 1)
        self.assertTrue(payload["truncated"])
        self.assertEqual(payload["elements"][0]["name"], "Kitchen")

    def test_malformed_dump_lists_nothing(self):
        payload = control_actions.list_clickable("<not xml")
        self.assertEqual(
            payload, {"elements": [], "count": 0, "truncated": False}
        )


if __name__ == "__main__":
    unittest.main()
