"""
Session Management - Persistent Campaign Tracking & Job Queue
Session Restoration, Job Scheduling, State Persistence
"""

import json
import logging
import pickle
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import deque

logger = logging.getLogger("Khora.Sessions")

class SessionManager:
    """Manage persistent Khora sessions"""
    
    def __init__(self):
        self.sessions = {}
        self.current_session = None
        
        Path("sessions").mkdir(exist_ok=True)
        Path("jobs").mkdir(exist_ok=True)
        self._load_sessions()
    
    def create_session(self, target: str, assessor: str = "Unknown", 
                      notes: str = None) -> str:
        """Create new assessment session"""
        session_id = str(uuid.uuid4())[:8]
        
        session = {
            'id': session_id,
            'target': target,
            'assessor': assessor,
            'notes': notes,
            'created_at': datetime.now().isoformat(),
            'started_at': None,
            'ended_at': None,
            'status': 'initialized',
            'modules_executed': [],
            'findings': [],
            'evidence': [],
            'compromises': []
        }
        
        self.sessions[session_id] = session
        self.current_session = session_id
        self._save_session(session_id)
        
        logger.info(f"Created session {session_id} for {target}")
        print(f"[+] Session created: {session_id}")
        print(f"    Target: {target}")
        print(f"    Assessor: {assessor}")
        
        return session_id
    
    def get_session(self, session_id: str) -> Optional[Dict]:
        """Retrieve session by ID"""
        return self.sessions.get(session_id)
    
    def start_session(self, session_id: str):
        """Start/resume session"""
        if session_id not in self.sessions:
            logger.error(f"Session not found: {session_id}")
            return False
        
        session = self.sessions[session_id]
        session['status'] = 'active'
        session['started_at'] = datetime.now().isoformat()
        self.current_session = session_id
        self._save_session(session_id)
        
        logger.info(f"Session started: {session_id}")
        print(f"[+] Session {session_id} started")
        return True
    
    def end_session(self, session_id: str):
        """End session"""
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        session['status'] = 'completed'
        session['ended_at'] = datetime.now().isoformat()
        self._save_session(session_id)
        
        logger.info(f"Session ended: {session_id}")
        print(f"[+] Session {session_id} ended")
        return True
    
    def log_module_execution(self, module: str, status: str, result: Dict = None):
        """Log module execution in current session"""
        if not self.current_session:
            return
        
        session = self.sessions[self.current_session]
        execution = {
            'module': module,
            'status': status,
            'timestamp': datetime.now().isoformat(),
            'result': result or {}
        }
        
        session['modules_executed'].append(execution)
        self._save_session(self.current_session)
        logger.info(f"Module {module} logged: {status}")
    
    def add_finding(self, severity: str, title: str, description: str):
        """Add finding to current session"""
        if not self.current_session:
            return
        
        session = self.sessions[self.current_session]
        finding = {
            'severity': severity,
            'title': title,
            'description': description,
            'timestamp': datetime.now().isoformat()
        }
        
        session['findings'].append(finding)
        self._save_session(self.current_session)
        logger.info(f"Finding added: [{severity}] {title}")
    
    def add_compromise(self, system_name: str, method: str, access_level: str):
        """Log compromised system"""
        if not self.current_session:
            return
        
        session = self.sessions[self.current_session]
        compromise = {
            'system': system_name,
            'method': method,
            'access_level': access_level,
            'timestamp': datetime.now().isoformat()
        }
        
        session['compromises'].append(compromise)
        self._save_session(self.current_session)
        logger.info(f"System compromised: {system_name} ({method})")
    
    def _save_session(self, session_id: str):
        """Persist session to disk"""
        try:
            session_file = Path("sessions") / f"{session_id}.json"
            with open(session_file, 'w') as f:
                json.dump(self.sessions[session_id], f, indent=2)
        except Exception as e:
            logger.error(f"Session save failed: {e}")
    
    def _load_sessions(self):
        """Load all sessions from disk"""
        try:
            sessions_dir = Path("sessions")
            for session_file in sessions_dir.glob("*.json"):
                with open(session_file) as f:
                    session = json.load(f)
                    self.sessions[session['id']] = session
            
            logger.info(f"Loaded {len(self.sessions)} sessions")
        except Exception as e:
            logger.error(f"Session load failed: {e}")
    
    def list_sessions(self) -> List[Dict]:
        """List all sessions"""
        sessions_list = []
        for session_id, session in self.sessions.items():
            sessions_list.append({
                'id': session_id,
                'target': session['target'],
                'status': session['status'],
                'created': session['created_at'],
                'findings': len(session['findings']),
                'compromises': len(session['compromises'])
            })
        
        return sorted(sessions_list, key=lambda x: x['created'], reverse=True)
    
    def export_session(self, session_id: str, format: str = 'json') -> Optional[Path]:
        """Export session to file"""
        if session_id not in self.sessions:
            return None
        
        try:
            timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
            session = self.sessions[session_id]
            
            if format == 'json':
                export_file = Path("reports") / f"session_{session_id}_{timestamp}.json"
                with open(export_file, 'w') as f:
                    json.dump(session, f, indent=2)
            
            logger.info(f"Session exported: {export_file}")
            return export_file
        except Exception as e:
            logger.error(f"Session export failed: {e}")
            return None


class JobQueue:
    """Manage exploitation jobs and scheduling"""
    
    def __init__(self):
        self.jobs = deque()
        self.completed_jobs = []
        self.failed_jobs = []
    
    def add_job(self, job_type: str, target: str, module: str, 
               params: Dict = None, priority: int = 5) -> str:
        """Add job to queue"""
        job_id = str(uuid.uuid4())[:8]
        
        job = {
            'id': job_id,
            'type': job_type,  # 'exploit', 'recon', 'brute_force', etc.
            'target': target,
            'module': module,
            'params': params or {},
            'priority': priority,
            'status': 'queued',
            'created_at': datetime.now().isoformat(),
            'scheduled_for': None,
            'started_at': None,
            'completed_at': None,
            'result': None
        }
        
        self.jobs.append(job)
        logger.info(f"Job added: {job_id} - {job_type}({module})")
        return job_id
    
    def schedule_job(self, job_id: str, delay_minutes: int = 0) -> bool:
        """Schedule job for future execution"""
        scheduled_time = datetime.now() + timedelta(minutes=delay_minutes)
        
        # Find and update job
        for job in self.jobs:
            if job['id'] == job_id:
                job['scheduled_for'] = scheduled_time.isoformat()
                job['status'] = 'scheduled'
                logger.info(f"Job scheduled: {job_id} for {scheduled_time}")
                return True
        
        return False
    
    def get_next_job(self) -> Optional[Dict]:
        """Get next job from queue"""
        if not self.jobs:
            return None
        
        # Sort by priority and scheduled time
        job = max(self.jobs, key=lambda x: x['priority'])
        
        if job['scheduled_for']:
            scheduled = datetime.fromisoformat(job['scheduled_for'])
            if datetime.now() >= scheduled:
                self.jobs.remove(job)
                return job
        else:
            self.jobs.remove(job)
            return job
        
        return None
    
    def mark_completed(self, job_id: str, result: Dict = None):
        """Mark job as completed"""
        for job in self.completed_jobs + self.failed_jobs:
            if job['id'] == job_id:
                job['completed_at'] = datetime.now().isoformat()
                job['result'] = result
                logger.info(f"Job marked completed: {job_id}")
                return
    
    def get_queue_status(self) -> Dict:
        """Get queue status"""
        return {
            'queued': len(self.jobs),
            'completed': len(self.completed_jobs),
            'failed': len(self.failed_jobs),
            'queue': list(self.jobs)[:10]  # Show first 10
        }


# Global session manager instance
_session_manager = SessionManager()
_job_queue = JobQueue()


def print_sessions():
    """Print all sessions"""
    sessions = _session_manager.list_sessions()
    
    if not sessions:
        print("[!] No sessions found")
        return
    
    print(f"\n{'='*70}")
    print("KHORA SESSIONS".center(70))
    print('='*70)
    print(f"{'ID':<12} {'Target':<20} {'Status':<15} {'Findings':<10}")
    print('-'*70)
    
    for session in sessions:
        print(f"{session['id']:<12} {session['target']:<20} " + 
              f"{session['status']:<15} {session['findings']:<10}")
    
    print('='*70 + "\n")


def resume_session(session_id: str) -> bool:
    """Resume existing session"""
    session = _session_manager.get_session(session_id)
    if session:
        _session_manager.start_session(session_id)
        return True
    return False


def get_session_summary(session_id: str) -> Dict:
    """Get session summary"""
    session = _session_manager.get_session(session_id)
    if not session:
        return {}
    
    return {
        'id': session['id'],
        'target': session['target'],
        'duration': (datetime.fromisoformat(session['ended_at']) - 
                    datetime.fromisoformat(session['started_at'])).total_seconds() 
                    if session['ended_at'] and session['started_at'] else None,
        'modules_executed': len(session['modules_executed']),
        'total_findings': len(session['findings']),
        'systems_compromised': len(session['compromises']),
        'status': session['status']
    }
