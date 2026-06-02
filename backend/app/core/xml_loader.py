import os
import xml.etree.ElementTree as ET


class XMLConfig:
    def __init__(self, file_path: str):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Config file not found: {file_path}")

        self.file_path = file_path
        self.tree = ET.parse(file_path)
        self.root = self.tree.getroot()

    def get(self, section: str, key: str, fallback=None, cast_type=None):
        """
        Get value from XML config

        Args:
            section (str): XML section
            key (str): Key inside section
            fallback (any): default value if not found
            cast_type (type): convert value (int, bool, etc.)

        Returns:
            value
        """

        section_node = self.root.find(section)
        if section_node is None:
            return fallback

        key_node = section_node.find(key)
        if key_node is None:
            return fallback

        value = key_node.text

        # Handle ENV variables like ${VAR}
        if value and value.startswith("${") and value.endswith("}"):
            env_key = value[2:-1]
            value = os.getenv(env_key, fallback)

        # Type casting
        if cast_type and value is not None:
            try:
                if cast_type == bool:
                    return str(value).lower() in ["true", "1", "yes"]
                return cast_type(value)
            except Exception:
                return fallback

        return value


# -------------------------
# Load Config
# -------------------------
CONFIG_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "config",
    "config.xml"
)

config = XMLConfig(CONFIG_PATH)
