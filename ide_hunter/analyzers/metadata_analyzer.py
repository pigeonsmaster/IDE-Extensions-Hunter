"""
Extension metadata extraction
"""

import json
import logging
import aiofiles
from pathlib import Path
import xml.etree.ElementTree as ET
import re
import zipfile
import tempfile
import shutil

from ide_hunter.models import ExtensionMetadata

logger = logging.getLogger(__name__)


class MetadataAnalyzer:
    """Extracts metadata from extension files."""

    async def extract_metadata(
        self, extension_path: Path, metadata: ExtensionMetadata
    ) -> None:
        """Extract metadata from an extension directory."""
        # Check for JAR files in multiple possible locations
        jar_locations = [
            extension_path / "lib",  # Standard lib directory
            extension_path,  # Root directory
            extension_path / "META-INF",  # META-INF directory
            extension_path / "resources",  # Resources directory
            extension_path / "classes",  # Classes directory
            extension_path / "dist",  # Distribution directory
        ]

        # Try each location for JAR files
        for location in jar_locations:
            if location.exists():
                jar_files = list(location.glob("*.jar"))
                if jar_files:
                    logger.debug(f"Found JAR files in {location}: {jar_files}")
                    # Sort JAR files to process the main plugin JAR first
                    jar_files.sort(key=lambda x: x.name)
                    for jar_file in jar_files:
                        try:
                            # Skip known dependency JARs
                            if any(dep in jar_file.name.lower() for dep in ['annotations', 'commons', 'gson', 'kotlin', 'ktor']):
                                logger.debug(f"Skipping dependency JAR: {jar_file}")
                                continue
                                
                            await self.extract_from_jar(jar_file, metadata)
                            if metadata.name and metadata.version:  # Stop if we found valid metadata
                                logger.debug(f"Successfully extracted metadata from {jar_file}")
                                return
                        except Exception as e:
                            logger.warning(f"Error extracting metadata from JAR {jar_file}: {e}")
                            continue

        # If no JAR files or extraction failed, try different metadata file formats
        metadata_files = [
            extension_path / "plugin.xml",  # Root plugin.xml
            extension_path / "META-INF" / "plugin.xml",  # META-INF plugin.xml
            extension_path / "resources" / "META-INF" / "plugin.xml",  # Resources META-INF plugin.xml
            extension_path / "build.gradle",  # Gradle build file
            extension_path / "plugin.properties",  # Properties file
        ]

        for file_path in metadata_files:
            if file_path.exists():
                try:
                    if file_path.name == "plugin.xml":
                        await self.extract_from_plugin_xml(file_path, metadata)
                    elif file_path.name == "build.gradle":
                        await self.extract_from_gradle(file_path, metadata)
                    elif file_path.name == "plugin.properties":
                        await self.extract_from_properties(file_path, metadata)
                    if metadata.name and metadata.version:  # Stop if we found valid metadata
                        return
                except Exception as e:
                    logger.warning(f"Error extracting metadata from {file_path}: {e}")
                    continue

        logger.warning(f"No metadata file found in {extension_path}")

    async def extract_from_jar(self, jar_path: Path, metadata: ExtensionMetadata) -> None:
        """Extract metadata from a JAR file."""
        try:
            logger.debug(f"Attempting to extract metadata from JAR: {jar_path}")
            with zipfile.ZipFile(jar_path, 'r') as jar:
                logger.debug(f"JAR contents: {jar.namelist()}")
                
                # 1. First try standard locations for plugin.xml
                plugin_xml_locations = [
                    'META-INF/plugin.xml',
                    'plugin.xml',
                    'resources/META-INF/plugin.xml'
                ]
                
                for location in plugin_xml_locations:
                    try:
                        logger.debug(f"Checking for plugin.xml at: {location}")
                        if location in jar.namelist():
                            logger.debug(f"Found plugin.xml at: {location}")
                            content = jar.read(location).decode('utf-8')
                            await self.extract_from_plugin_xml_content(content, metadata)
                            return  # Stop after first successful extraction
                    except Exception as e:
                        logger.warning(f"Error reading {location} from {jar_path}: {e}")
                        continue

                # 2. Try plugin.properties as fallback
                properties_locations = [
                    'META-INF/plugin.properties',
                    'plugin.properties'
                ]
                
                for location in properties_locations:
                    try:
                        logger.debug(f"Checking for plugin.properties at: {location}")
                        if location in jar.namelist():
                            logger.debug(f"Found plugin.properties at: {location}")
                            content = jar.read(location).decode('utf-8')
                            await self.extract_from_properties_content(content, metadata)
                            return
                    except Exception as e:
                        logger.warning(f"Error reading {location} from {jar_path}: {e}")
                        continue

                # 3. If no metadata files found, try to extract from JAR name
                jar_name = jar_path.stem
                logger.debug(f"Attempting to extract metadata from JAR name: {jar_name}")
                if "-" in jar_name:
                    parts = jar_name.split("-")
                    if len(parts) >= 2:
                        metadata.name = parts[0]
                        metadata.version = parts[1]
                        logger.debug(f"Extracted name and version from JAR name: {metadata.name} {metadata.version}")

        except zipfile.BadZipFile as e:
            logger.error(f"Invalid JAR file {jar_path}: {e}")
        except Exception as e:
            logger.error(f"Error extracting metadata from JAR {jar_path}: {e}")
            raise

    async def extract_from_plugin_xml_content(self, content: str, metadata: ExtensionMetadata) -> None:
        """Extract metadata from plugin.xml content."""
        try:
            root = ET.fromstring(content)
            
            # Extract name
            name_elem = root.find("name")
            if name_elem is not None and name_elem.text:
                metadata.name = name_elem.text.strip()
                logger.debug(f"Found name: {metadata.name}")

            # Extract version
            version_elem = root.find("version")
            if version_elem is not None and version_elem.text:
                metadata.version = version_elem.text.strip()
                logger.debug(f"Found version: {metadata.version}")

            # Extract vendor/publisher
            vendor_elem = root.find("vendor")
            if vendor_elem is not None and vendor_elem.text:
                metadata.publisher = vendor_elem.text.strip()
                logger.debug(f"Found publisher: {metadata.publisher}")

            # Extract URLs
            url_elem = root.find("url")
            if url_elem is not None and url_elem.text:
                metadata.urls["Homepage"] = url_elem.text.strip()
                logger.debug(f"Found URL: {url_elem.text.strip()}")

        except ET.ParseError as e:
            logger.error(f"Error parsing plugin.xml content: {e}")
            raise

    async def extract_from_properties_content(self, content: str, metadata: ExtensionMetadata) -> None:
        """Extract metadata from properties content."""
        try:
            for line in content.splitlines():
                if "=" in line:
                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip()

                    if key == "version":
                        metadata.version = value
                        logger.debug(f"Found version: {value}")
                    elif key == "vendor":
                        metadata.publisher = value
                        logger.debug(f"Found publisher: {value}")
                    elif key == "name":
                        metadata.name = value
                        logger.debug(f"Found name: {value}")
                    elif key == "url":
                        metadata.urls["Homepage"] = value
                        logger.debug(f"Found URL: {value}")

        except Exception as e:
            logger.error(f"Error parsing properties content: {e}")
            raise

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
            logger.debug(f"Extracting metadata from {file_path}")
            tree = ET.parse(file_path)
            root = tree.getroot()

            # Extract name
            name_elem = root.find("name")
            if name_elem is not None and name_elem.text:
                metadata.name = name_elem.text.strip()
                logger.debug(f"Found name: {metadata.name}")

            # Extract version
            version_elem = root.find("version")
            if version_elem is not None and version_elem.text:
                metadata.version = version_elem.text.strip()
                logger.debug(f"Found version: {metadata.version}")

            # Extract vendor/publisher
            vendor_elem = root.find("vendor")
            if vendor_elem is not None and vendor_elem.text:
                metadata.publisher = vendor_elem.text.strip()
                logger.debug(f"Found publisher: {metadata.publisher}")

            # Extract description if available
            description_elem = root.find("description")
            if description_elem is not None and description_elem.text:
                logger.debug(f"Found description: {description_elem.text.strip()}")

            # Extract URLs if available
            url_elem = root.find("url")
            if url_elem is not None and url_elem.text:
                metadata.urls["Homepage"] = url_elem.text.strip()
                logger.debug(f"Found URL: {url_elem.text.strip()}")

        except ET.ParseError as e:
            logger.error(f"Error parsing plugin.xml {file_path}: {e}")
        except Exception as e:
            logger.error(f"Error extracting metadata from plugin.xml {file_path}: {e}")

    async def extract_from_gradle(
        self, file_path: Path, metadata: ExtensionMetadata
    ) -> None:
        """Extract metadata from build.gradle file."""
        try:
            async with aiofiles.open(file_path, "r", encoding="utf-8") as f:
                content = await f.read()

                # Extract version using regex
                version_match = re.search(r'version\s*=\s*[\'"]([^\'"]+)[\'"]', content)
                if version_match:
                    metadata.version = version_match.group(1)
                    logger.debug(f"Found version: {metadata.version}")

                # Extract group/org using regex
                group_match = re.search(r'group\s*=\s*[\'"]([^\'"]+)[\'"]', content)
                if group_match:
                    metadata.publisher = group_match.group(1)
                    logger.debug(f"Found publisher: {metadata.publisher}")

                # Extract URLs from repositories
                url_matches = re.finditer(r'url\s*=\s*[\'"](https?://[^\'"]+)[\'"]', content)
                for match in url_matches:
                    url = match.group(1)
                    metadata.urls["Repository"] = url
                    logger.debug(f"Found URL: {url}")

        except Exception as e:
            logger.error(f"Error extracting metadata from build.gradle {file_path}: {e}")

    async def extract_from_properties(
        self, file_path: Path, metadata: ExtensionMetadata
    ) -> None:
        """Extract metadata from plugin.properties file."""
        try:
            async with aiofiles.open(file_path, "r", encoding="utf-8") as f:
                content = await f.read()
                await self.extract_from_properties_content(content, metadata)

        except Exception as e:
            logger.error(f"Error extracting metadata from plugin.properties {file_path}: {e}")

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
