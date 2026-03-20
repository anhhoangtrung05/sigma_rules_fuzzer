import subprocess
import os
from typing import List, Dict
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ExecuteAgent:
    """
    Execute a batch of commands from output files.
    Used for testing fuzzing output in controlled environment.
    """
    
    def __init__(self, shell: str = 'cmd', timeout: int = 10):
        """
        Initialize ExecuteAgent.
        
        Args:
            shell: Shell to use ('cmd', 'powershell', 'pwsh')
            timeout: Timeout for each command execution in seconds
        """
        self.shell = shell
        self.timeout = timeout
        
    def execute_command(self, command: str) -> Dict:
        """
        Execute a single command and log output.
        
        Args:
            command: The command to execute
            
        Returns:
            Dict with command, return_code, stdout, stderr
        """
        result = {
            'command': command,
            'return_code': None,
            'stdout': '',
            'stderr': ''
        }
        
        try:
            logger.info(f"Executing: {command}")
            
            process = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            result['return_code'] = process.returncode
            result['stdout'] = process.stdout
            result['stderr'] = process.stderr
            
            #if process.stdout:
                #logger.info(f"STDOUT:\n{process.stdout}")
            #if process.stderr:
                #logger.warning(f"STDERR:\n{process.stderr}")
            
            logger.info(f"Return code: {process.returncode}\n")
                
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out after {self.timeout}s\n")
            
        except Exception as e:
            logger.error(f"Execution error: {e}\n")
        
        return result
    
    def execute_from_file(self, file_path: str) -> List[Dict]:
        """
        Execute commands from a file (one command per line).
        
        Args:
            file_path: Path to file containing commands
            
        Returns:
            List of execution results
        """
        results = []
        
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return results
        
        logger.info(f"Loading commands from: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                commands = f.readlines()
            
            for i, cmd in enumerate(commands, 1):
                cmd = cmd.strip()
                if not cmd or cmd.startswith('#'):
                    continue
                
                result = self.execute_command(cmd)
                results.append(result)
        
        except Exception as e:
            logger.error(f"Error reading file: {e}")
        
        return results
    
    def execute_batch(self, file_list: List[str]) -> Dict:
        """
        Execute commands from multiple files.
        
        Args:
            file_list: List of file paths to execute
            
        Returns:
            Dict with summary of all executions
        """
        summary = {
            'total_files': len(file_list),
            'total_commands': 0,
            'successful': 0,
            'failed': 0
        }
        
        for file_path in file_list:
            logger.info(f"\n{'='*60}")
            logger.info(f"Processing: {file_path}")
            logger.info(f"{'='*60}\n")
            
            results = self.execute_from_file(file_path)
            
            successful = sum(1 for r in results if r['return_code'] == 0)
            failed = sum(1 for r in results if r['return_code'] != 0)
            
            summary['total_commands'] += len(results)
            summary['successful'] += successful
            summary['failed'] += failed
        
        logger.info(f"\n{'='*60}")
        logger.info(f"Summary: {summary['successful']}/{summary['total_commands']} successful, {summary['failed']} failed")
        logger.info(f"{'='*60}\n")
        
        return summary


if __name__ == '__main__':
    # Example usage
    agent = ExecuteAgent(shell='cmd', timeout=10)
    print("ExecuteAgent initialized successfully")

