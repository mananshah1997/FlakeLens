"""
Grafana Dashboard Snowflake Table Extractor

This module extracts Snowflake table references from Grafana dashboard JSON files.
It parses both panel queries and template variable queries, using sqlglot for 
accurate SQL parsing with regex fallback for complex cases.

Author: Manan Tarun Shah - Production Technology
Version: 1.0
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass

from sqlglot import parse_one, exp
from sqlglot.errors import ParseError


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class QueryInfo:
    """Represents a query found in a Grafana dashboard."""
    title: str
    query: str
    source_type: str  # 'panel' or 'variable'


@dataclass
class ExtractionResult:
    """Result of table extraction for a single query."""
    query_info: QueryInfo
    tables: Set[str]
    success: bool
    error_message: Optional[str] = None


class GrafanaTableExtractor:
    """Extracts Snowflake table references from Grafana dashboard JSON."""
    
    # Grafana macro patterns to clean
    GRAFANA_MACROS = [
        (r"\$__time\w*\([^\)]*\)", "CURRENT_TIMESTAMP"),
        (r"\$__interval\w*", "'1h'"),
        (r"\$\{[^\}]+\}", "'dummy'"),
        (r"\$\w+", "'dummy'"),
    ]
    
    # Regex patterns for table extraction fallback
    TABLE_PATTERNS = [
        r'(?:FROM|JOIN)\s+([A-Za-z0-9_]+\.[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)?)',
        r'"([A-Za-z0-9_]+)"\."([A-Za-z0-9_]+)"(?:\."([A-Za-z0-9_]+)")?',
    ]
    
    def __init__(self, input_folder: str = "Input"):
        """
        Initialize the extractor.
        
        Args:
            input_folder: Path to folder containing Grafana JSON files
        """
        self.input_folder = Path(input_folder)
        self._validate_input_folder()
    
    def _validate_input_folder(self) -> None:
        """Validate that input folder exists and contains files."""
        if not self.input_folder.exists():
            raise FileNotFoundError(f"Input folder not found: {self.input_folder}")
        
        files = list(self.input_folder.glob("*.json"))
        if not files:
            raise ValueError(f"No JSON files found in {self.input_folder}")
    
    def load_dashboard(self, file_path: Path) -> Dict:
        """
        Load and parse a Grafana dashboard JSON file.
        
        Args:
            file_path: Path to the JSON file
            
        Returns:
            Parsed dashboard dictionary
            
        Raises:
            json.JSONDecodeError: If file is not valid JSON
        """
        logger.info(f"Loading dashboard from: {file_path}")
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def extract_queries(self, dashboard: Dict) -> List[QueryInfo]:
        """
        Extract all queries from dashboard including panels and variables.
        
        Args:
            dashboard: Parsed Grafana dashboard dictionary
            
        Returns:
            List of QueryInfo objects
        """
        queries = []
        
        # Extract variable queries
        queries.extend(self._extract_variable_queries(dashboard))
        
        # Extract panel queries
        queries.extend(self._extract_panel_queries(dashboard))
        
        logger.info(f"Extracted {len(queries)} queries from dashboard")
        return queries
    
    def _extract_variable_queries(self, dashboard: Dict) -> List[QueryInfo]:
        """Extract queries from template variables (only variables with actual queries)."""
        queries = []
        
        templating = dashboard.get('templating', {})
        variables = templating.get('list', [])
        
        for variable in variables:
            if not isinstance(variable, dict):
                continue
            
            var_name = variable.get('name', 'Unknown')
            query = variable.get('query')
            
            # Only include variables that have non-empty queries
            if query:
                # Handle both string and dict queries
                if isinstance(query, str) and query.strip():
                    queries.append(QueryInfo(
                        title=f"Variable: {var_name}",
                        query=query,
                        source_type='variable'
                    ))
                elif isinstance(query, dict) and 'rawSql' in query and query['rawSql'].strip():
                    queries.append(QueryInfo(
                        title=f"Variable: {var_name}",
                        query=query['rawSql'],
                        source_type='variable'
                    ))
        
        return queries
    
    def _extract_panel_queries(self, dashboard: Dict) -> List[QueryInfo]:
        """Extract queries from dashboard panels."""
        queries = []
        panels = dashboard.get('panels', [])
        
        for panel in panels:
            if not isinstance(panel, dict):
                continue
            
            # Extract from top-level panel
            queries.extend(self._extract_from_panel(panel))
            
            # Handle nested panels (row panels)
            nested_panels = panel.get('panels', [])
            for nested_panel in nested_panels:
                if isinstance(nested_panel, dict):
                    queries.extend(self._extract_from_panel(nested_panel))
        
        return queries
    
    def _extract_from_panel(self, panel: Dict) -> List[QueryInfo]:
        """Extract queries from a single panel."""
        queries = []
        panel_title = panel.get('title', 'Untitled Panel')
        targets = panel.get('targets', [])
        
        for target in targets:
            if isinstance(target, dict) and 'rawSql' in target:
                queries.append(QueryInfo(
                    title=panel_title,
                    query=target['rawSql'],
                    source_type='panel'
                ))
        
        return queries
    
    def clean_query(self, query: str) -> str:
        """
        Clean Grafana-specific macros and variables from SQL query.
        
        Args:
            query: Raw SQL query string
            
        Returns:
            Cleaned query string
        """
        cleaned = query
        for pattern, replacement in self.GRAFANA_MACROS:
            cleaned = re.sub(pattern, replacement, cleaned)
        return cleaned
    
    def extract_tables_with_sqlglot(self, query: str) -> Set[str]:
        """
        Extract table names using sqlglot parser.
        
        Args:
            query: SQL query string
            
        Returns:
            Set of fully qualified table names
            
        Raises:
            ParseError: If sqlglot cannot parse the query
        """
        tree = parse_one(query, read='snowflake')
        tables = set()
        
        for table in tree.find_all(exp.Table):
            parts = []
            if table.catalog:
                parts.append(table.catalog)
            if table.db:
                parts.append(table.db)
            parts.append(table.name)
            tables.add('.'.join(parts))
        
        return tables
    
    def extract_tables_with_regex(self, query: str) -> Set[str]:
        """
        Extract table names using regex patterns (fallback method).
        
        Args:
            query: SQL query string
            
        Returns:
            Set of table names found via regex
        """
        tables = set()
        
        for pattern in self.TABLE_PATTERNS:
            matches = re.findall(pattern, query, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    table = '.'.join(filter(None, match))
                else:
                    table = match
                if table:
                    tables.add(table)
        
        return tables
    
    def extract_tables(self, query_info: QueryInfo) -> ExtractionResult:
        """
        Extract tables from a query using sqlglot with regex fallback.
        
        Args:
            query_info: QueryInfo object containing the query
            
        Returns:
            ExtractionResult with tables and status
        """
        try:
            cleaned_query = self.clean_query(query_info.query)
            
            # Try sqlglot first
            try:
                tables = self.extract_tables_with_sqlglot(cleaned_query)
                
                # If sqlglot found nothing, try regex
                if not tables:
                    tables = self.extract_tables_with_regex(cleaned_query)
                    
            except ParseError as e:
                # Fallback to regex if sqlglot fails
                logger.debug(f"sqlglot parse failed for '{query_info.title}', using regex fallback")
                tables = self.extract_tables_with_regex(cleaned_query)
            
            return ExtractionResult(
                query_info=query_info,
                tables=tables,
                success=True
            )
            
        except Exception as e:
            logger.error(f"Failed to extract tables from '{query_info.title}': {str(e)}")
            return ExtractionResult(
                query_info=query_info,
                tables=set(),
                success=False,
                error_message=str(e)
            )
    
    def process_dashboard(self, file_path: Path) -> Tuple[str, List[ExtractionResult]]:
        """
        Process a complete dashboard file and extract all tables.
        
        Args:
            file_path: Path to Grafana JSON file
            
        Returns:
            Tuple of (dashboard_name, list of ExtractionResults)
        """
        dashboard = self.load_dashboard(file_path)
        dashboard_name = dashboard.get('title', 'Unknown Dashboard')
        
        queries = self.extract_queries(dashboard)
        results = [self.extract_tables(query_info) for query_info in queries]
        
        return dashboard_name, results
    
    def format_output(self, dashboard_name: str, results: List[ExtractionResult]) -> None:
        """
        Print formatted extraction results.
        
        Args:
            dashboard_name: Name of the dashboard
            results: List of extraction results
        """
        # Count query types (only those with tables found)
        variable_queries_with_tables = sum(1 for r in results if r.query_info.source_type == 'variable' and r.success and r.tables)
        panel_queries_with_tables = sum(1 for r in results if r.query_info.source_type == 'panel' and r.success and r.tables)
        
        # Count queries without tables
        variable_queries_no_tables = sum(1 for r in results if r.query_info.source_type == 'variable' and r.success and not r.tables)
        panel_queries_no_tables = sum(1 for r in results if r.query_info.source_type == 'panel' and r.success and not r.tables)
        
        # Count failed queries
        failed_queries = sum(1 for r in results if not r.success)
        
        print(f"\n{'='*80}")
        print(f"📊 Dashboard: {dashboard_name}")
        print(f"{'='*80}\n")
        print(f"Query Statistics:")
        print(f"  ✓ {variable_queries_with_tables + panel_queries_with_tables} queries with tables found")
        print(f"    • {panel_queries_with_tables} panel queries")
        print(f"    • {variable_queries_with_tables} variable queries")
        print(f"  ⚠ {variable_queries_no_tables + panel_queries_no_tables} queries with no tables")
        print(f"    • {panel_queries_no_tables} panel queries")
        print(f"    • {variable_queries_no_tables} variable queries")
        if failed_queries > 0:
            print(f"  ✗ {failed_queries} queries failed to parse")
        print()
        
        all_tables = set()
        table_usage = {}
        
        for result in results:
            if result.success:
                if result.tables:
                    print(f"✓ {result.query_info.title}")
                    for table in sorted(result.tables):
                        print(f"    └─ {table}")
                        all_tables.add(table)
                        # Track usage with source type
                        if table not in table_usage:
                            table_usage[table] = {'panels': set(), 'variables': set()}
                        
                        if result.query_info.source_type == 'panel':
                            table_usage[table]['panels'].add(result.query_info.title)
                        else:
                            table_usage[table]['variables'].add(result.query_info.title)
                else:
                    print(f"⚠ {result.query_info.title}")
                    print(f"    └─ No tables found")
            else:
                print(f"✗ {result.query_info.title}")
                print(f"    └─ Error: {result.error_message[:80]}")
            print()
        
        # Print summary with smart deduplication
        print(f"\n{'='*80}")
        print(f"📋 SUMMARY - All Unique Tables")
        print(f"{'='*80}\n")
        
        if all_tables:
            # Deduplicate: prefer longer (more specific) table names
            deduplicated_tables = set()
            sorted_tables = sorted(all_tables, key=lambda x: x.count('.'), reverse=True)
            
            for table in sorted_tables:
                # Check if this table is a suffix of any already added table
                is_duplicate = False
                for existing in deduplicated_tables:
                    if existing.endswith('.' + table):
                        is_duplicate = True
                        break
                
                if not is_duplicate:
                    deduplicated_tables.add(table)
            
            print(f"Total: {len(deduplicated_tables)} unique tables\n")
            
            # Print deduplicated tables
            for table in sorted(deduplicated_tables):
                # Count usage across all variants of this table (ABC.DEF.GHI and DEF.GHI counted as one)
                panel_titles = set()
                variable_titles = set()
                
                # Find all table variants that match this table or are subsets of it
                for t in all_tables:
                    # Check if t is the same as table, or if table ends with .t (meaning t is a shorter version)
                    if t == table or table.endswith('.' + t):
                        usage = table_usage.get(t, {'panels': set(), 'variables': set()})
                        panel_titles.update(usage['panels'])
                        variable_titles.update(usage['variables'])
                
                panel_count = len(panel_titles)
                variable_count = len(variable_titles)
                
                # Build usage string
                usage_parts = []
                if panel_count > 0:
                    panel_plural = 'panel' if panel_count == 1 else 'panels'
                    usage_parts.append(f"{panel_count} {panel_plural}")
                if variable_count > 0:
                    var_plural = 'variable' if variable_count == 1 else 'variables'
                    usage_parts.append(f"{variable_count} {var_plural}")
                
                usage_str = " + ".join(usage_parts) if usage_parts else "0 uses"
                print(f"  🔹 {table} (used in {usage_str})")
        else:
            print("  No tables found in any queries")
        
        print(f"\n{'='*80}\n")
    
    def run(self) -> None:
        """Main execution method to process all dashboards in input folder."""
        json_files = list(self.input_folder.glob("*.json"))
        
        if not json_files:
            logger.warning(f"No JSON files found in {self.input_folder}")
            return
        
        for json_file in json_files:
            try:
                dashboard_name, results = self.process_dashboard(json_file)
                self.format_output(dashboard_name, results)
            except Exception as e:
                logger.error(f"Failed to process {json_file}: {str(e)}")


def main():
    """Main entry point for the script."""
    try:
        extractor = GrafanaTableExtractor(input_folder="Input")
        extractor.run()
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        raise


if __name__ == "__main__":
    main()