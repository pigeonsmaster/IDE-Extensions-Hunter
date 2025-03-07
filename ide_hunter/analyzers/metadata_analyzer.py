"""
Extension metadata extraction
"""

import json
import logging
import aiofiles
from pathlib import Path
import xml.etree.ElementTree as ET

from ide_hunter.models import ExtensionMetadata

logger = logging.getLogger(__name__)


class MetadataAnalyzer:
    """Extracts metadata from extension files."""

    async def extract_metadata(
        self, extension_path: Path, metadata: ExtensionMetadata
    ) -> None:
        """Extract metadata from an extension directory."""
        package_json_path = extension_path / "package.json"
        plugin_xml_path = extension_path / "plugin.xml"

        if package_json_path.exists():
            await self.extract_from_package_json(package_json_path, metadata)
        elif plugin_xml_path.exists():
            await self.extract_from_plugin_xml(plugin_xml_path, metadata)

    async def extract_from_package_json(
        self, file_path: Path, metadata: ExtensionMetadata
    ) -> None:
        """Extract metadata from package.json."""
        try:
            async with aiofiles.open(file_path, "r", encoding="utf-8") as f:
                content = await f.read()
                data = json.loads(content)

                metadata.version = data.get("version", "Unknown")
                metadata.publisher = data.get("publisher", "Unknown")

                if metadata.publisher == "Unknown" and "author" in data:
                    author = data["author"]
                    if isinstance(author, dict):
                        metadata.publisher = author.get("name", "Unknown")
                    else:
                        metadata.publisher = author  # Sometimes it's a string

                # Extract URLs
                self._extract_urls(data, metadata)

        except Exception as e:
            logger.error(
                f"Error extracting metadata from package.json {file_path}: {e}"
            )

    async def extract_from_plugin_xml(
        self, file_path: Path, metadata: ExtensionMetadata
    ) -> None:
        """Extract metadata from plugin.xml (PyCharm)."""
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

            name_elem = root.find("name")
            if name_elem is not None and name_elem.text:
                metadata.name = name_elem.text

            version_elem = root.find("version")
            if version_elem is not None and version_elem.text:
                metadata.version = version_elem.text

            vendor_elem = root.find("vendor")
            if vendor_elem is not None and vendor_elem.text:
                metadata.publisher = vendor_elem.text

        except Exception as e:
            logger.error(f"Error extracting metadata from plugin.xml {file_path}: {e}")

    def _extract_urls(self, data: dict, metadata: ExtensionMetadata) -> None:
        """Extract URLs from package data."""
        if not isinstance(data, dict):
            return

        url_fields = {
            "Repository": data.get("repository"),
            "Bug Tracker": data.get("bugs"),
            "Homepage": data.get("homepage"),
            "Publisher": data.get("publisher"),
            "Main": data.get("main"),
            "Browser": data.get("browser"),
        }

        for source, url in url_fields.items():
            if isinstance(url, dict):
                url = url.get("url")

            if url and isinstance(url, str):
                if url.startswith(("http://", "https://")):
                    metadata.urls[source] = url
