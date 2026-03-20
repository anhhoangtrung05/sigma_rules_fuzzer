import subprocess
import os
import json
from typing import List, Dict, Optional
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ZircoliteAgent:
    
    def __init__(self, rules_dir: str, events_dir: str = '.', zircolite_path: str = 'zircolite.py', output_dir: str = '.'):
        """
        Initialize ZircoliteAgent.
        """
        self.rules_dir = rules_dir
        self.events_dir = events_dir
        self.zircolite_path = zircolite_path
        self.output_dir = output_dir
        self.first_run = True
        self.results = []
        
    def load_rules(self) -> List[str]:
        """
        Load all Sigma rules from rules directory.
        
        Returns:
            List of rule file paths
        """
        rules = []
        
        if not os.path.exists(self.rules_dir):
            logger.error(f"Rules directory not found: {self.rules_dir}")
            return rules
        
        logger.info(f"Loading rules from: {self.rules_dir}")
        
        for root, dirs, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith('.yml') or file.endswith('.yaml'):
                    rule_path = os.path.join(root, file)
                    rules.append(rule_path)
        
        logger.info(f"Found {len(rules)} Sigma rules")
        return rules
    
    def check_events(self, events_file: str, rules: Optional[List[str]] = None) -> Dict:
        """
        Run Zircolite to check events file against rules.
        
        Args:
            events_file: Path to events file (JSON or JSONL format)
            rules: Optional list of specific rules to use. If None, loads all rules.
            
        Returns:
            Dict with detection results
        """
        result = {
            'events_file': events_file,
            'rules_count': 0,
            'detections': 0,
            'output_file': None,
            'success': False
        }
        
        if not os.path.exists(events_file):
            logger.error(f"Events file not found: {events_file}")
            result['error'] = f"Events file not found: {events_file}"
            return result
        
        if rules is None:
            rules = self.load_rules()
        
        result['rules_count'] = len(rules)
        
        if not rules:
            logger.warning("No rules found to check")
            result['error'] = "No rules found"
            return result
        
        output_file = os.path.join(
            self.output_dir,
            f"detection_{Path(events_file).stem}.json"
        )
        
        try:
            logger.info(f"Checking {events_file} against {len(rules)} rules")
            logger.info(f"Zircolite path: {self.zircolite_path}")
            
            # Build Zircolite command
            # zircolite.py -e events_file -r rules_dir -o output_json

            if self.first_run == True:
                cmd = [
                'python',
                self.zircolite_path,
                '-c', 'C:\BKCS\Zircolite\config\config.yaml',
                '-e', events_file,
                '-r', self.rules_dir,
                #'-sr',
                ]
                self.first_run = False
            
            else:
                cmd = [
                    'python',
                    self.zircolite_path,
                    '-c', 'C:\BKCS\Zircolite\config\config.yaml',
                    '-e', events_file,
                    '-r', 'C:\BKCS\Zircolite\\rules\compiled_rules.json',
                ]
            
            logger.info(f"Command: {' '.join(cmd)}")
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            if process.returncode == 0:
                logger.info(f"Zircolite execution successful")
                result['success'] = True
                result['output_file'] = output_file
                
                # Count detections from output
                if os.path.exists(output_file):
                    try:
                        with open(output_file, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                        result['detections'] = len(data)
                        logger.info(f"Found {result['detections']} detections")
                    except:
                        logger.warning("Could not parse Zircolite output")
            else:
                logger.error(f"Zircolite failed with code {process.returncode}")
                logger.error(f"STDERR: {process.stderr}")
                result['error'] = process.stderr
        
        except subprocess.TimeoutExpired:
            logger.error("Zircolite execution timed out")
            result['error'] = "Timeout"
        
        except Exception as e:
            logger.error(f"Error running Zircolite: {e}")
            result['error'] = str(e)
        
        return result
    
    def analyze_batch(self, events_files: List[str]) -> Dict:
        """
        Analyze multiple event files.
        
        Args:
            events_files: List of event file paths
            
        Returns:
            Dict with summary of all analyses
        """
        summary = {
            'total_files': len(events_files),
            'total_detections': 0,
            'successful': 0,
            'failed': 0,
            'results': []
        }
        
        rules = self.load_rules()
        
        for events_file in events_files:
            logger.info(f"\n{'='*60}")
            logger.info(f"Analyzing: {events_file}")
            logger.info(f"{'='*60}")
            
            result = self.check_events(events_file, rules)
            summary['results'].append(result)
            
            if result['success']:
                summary['successful'] += 1
                summary['total_detections'] += result['detections']
            else:
                summary['failed'] += 1
        
        logger.info(f"\n{'='*60}")
        logger.info(f"Summary: {summary['successful']}/{summary['total_files']} successful, {summary['total_detections']} total detections")
        logger.info(f"{'='*60}\n")
        
        return summary
    
    def save_summary(self, summary: Dict, output_path: str = None) -> str:
        """
        Save analysis summary to JSON file.
        
        Args:
            summary: Summary dict from analyze_batch()
            output_path: Path to save summary (default: zircolite_summary.json)
            
        Returns:
            Path to saved file
        """
        if output_path is None:
            output_path = os.path.join(self.output_dir, 'zircolite_summary.json')
        
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Summary saved to: {output_path}")
            return output_path
        
        except Exception as e:
            logger.error(f"Error saving summary: {e}")
            return None


if __name__ == '__main__':
    # Example usage
    agent = ZircoliteAgent(
        rules_dir='../Zircolite/rules',
        events_dir='./events',
        zircolite_path='../Zircolite/zircolite.py',
        output_dir='./zircolite_output'
    )
    
    print("ZircoliteAgent initialized successfully")
