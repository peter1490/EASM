use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    config::Settings,
    error::ApiError,
};

/// Task status enumeration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TaskStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Task type enumeration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TaskType {
    Scan,
    Discovery,
    AssetProcessing,
}

/// Task metadata and tracking information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskInfo {
    pub id: Uuid,
    pub task_type: TaskType,
    pub status: TaskStatus,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub progress: f32, // 0.0 to 1.0
    pub message: Option<String>,
    pub error: Option<String>,
    pub metadata: serde_json::Value,
}

impl TaskInfo {
    pub fn new(task_type: TaskType, metadata: serde_json::Value) -> Self {
        Self {
            id: Uuid::new_v4(),
            task_type,
            status: TaskStatus::Pending,
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            progress: 0.0,
            message: None,
            error: None,
            metadata,
        }
    }

    pub fn start(&mut self) {
        self.status = TaskStatus::Running;
        self.started_at = Some(Utc::now());
    }

    pub fn complete(&mut self) {
        self.status = TaskStatus::Completed;
        self.completed_at = Some(Utc::now());
        self.progress = 1.0;
    }

    pub fn fail(&mut self, error: String) {
        self.status = TaskStatus::Failed;
        self.completed_at = Some(Utc::now());
        self.error = Some(error);
    }

    pub fn cancel(&mut self) {
        self.status = TaskStatus::Cancelled;
        self.completed_at = Some(Utc::now());
    }

    pub fn update_progress(&mut self, progress: f32, message: Option<String>) {
        self.progress = progress.clamp(0.0, 1.0);
        self.message = message;
    }

    pub fn is_active(&self) -> bool {
        matches!(self.status, TaskStatus::Pending | TaskStatus::Running)
    }

    pub fn is_finished(&self) -> bool {
        matches!(self.status, TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled)
    }
}

/// Task execution context
pub struct TaskContext {
    pub task_id: Uuid,
    pub task_manager: Arc<TaskManager>,
}

impl TaskContext {
    pub async fn update_progress(&self, progress: f32, message: Option<String>) -> Result<(), ApiError> {
        self.task_manager.update_task_progress(self.task_id, progress, message).await
    }

    pub async fn check_cancellation(&self) -> Result<(), ApiError> {
        if self.task_manager.is_task_cancelled(self.task_id).await {
            Err(ApiError::Validation("Task was cancelled".to_string()))
        } else {
            Ok(())
        }
    }
}

/// Task execution function type
pub type TaskFunction = Box<dyn Fn(TaskContext) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ApiError>> + Send>> + Send + Sync>;

/// Background task manager with concurrency control and cancellation support
pub struct TaskManager {
    settings: Arc<Settings>,
    tasks: Arc<RwLock<HashMap<Uuid, TaskInfo>>>,
    active_handles: Arc<Mutex<HashMap<Uuid, JoinHandle<()>>>>,
    concurrency_semaphore: Arc<tokio::sync::Semaphore>,
}

impl TaskManager {
    pub fn new(settings: Arc<Settings>) -> Self {
        let max_concurrent = settings.max_concurrent_scans as usize;
        
        Self {
            settings,
            tasks: Arc::new(RwLock::new(HashMap::new())),
            active_handles: Arc::new(Mutex::new(HashMap::new())),
            concurrency_semaphore: Arc::new(tokio::sync::Semaphore::new(max_concurrent)),
        }
    }

    /// Submit a new task for execution
    pub async fn submit_task<F>(&self, task_type: TaskType, metadata: serde_json::Value, task_fn: F) -> Result<Uuid, ApiError>
    where
        F: Fn(TaskContext) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ApiError>> + Send>> + Send + Sync + 'static,
    {
        let task_info = TaskInfo::new(task_type.clone(), metadata);
        let task_id = task_info.id;

        // Store task info
        {
            let mut tasks = self.tasks.write().await;
            tasks.insert(task_id, task_info);
        }

        // Spawn background task
        let task_manager = Arc::new(self.clone());
        let semaphore = self.concurrency_semaphore.clone();
        
        let handle = tokio::spawn(async move {
            // Acquire semaphore permit for concurrency control
            let _permit = semaphore.acquire().await.unwrap();
            
            // Create task context
            let context = TaskContext {
                task_id,
                task_manager: task_manager.clone(),
            };

            // Mark task as started
            if let Err(e) = task_manager.start_task(task_id).await {
                tracing::error!("Failed to start task {}: {}", task_id, e);
                return;
            }

            // Execute the task
            match task_fn(context).await {
                Ok(()) => {
                    if let Err(e) = task_manager.complete_task(task_id).await {
                        tracing::error!("Failed to complete task {}: {}", task_id, e);
                    }
                }
                Err(e) => {
                    if let Err(err) = task_manager.fail_task(task_id, e.to_string()).await {
                        tracing::error!("Failed to mark task {} as failed: {}", task_id, err);
                    }
                }
            }

            // Remove from active handles
            {
                let mut handles = task_manager.active_handles.lock().await;
                handles.remove(&task_id);
            }
        });

        // Store the handle
        {
            let mut handles = self.active_handles.lock().await;
            handles.insert(task_id, handle);
        }

        tracing::info!("Submitted task {} of type {:?}", task_id, task_type);
        Ok(task_id)
    }

    /// Get task information by ID
    pub async fn get_task(&self, task_id: Uuid) -> Option<TaskInfo> {
        let tasks = self.tasks.read().await;
        tasks.get(&task_id).cloned()
    }

    /// List all tasks with optional filtering
    pub async fn list_tasks(&self, task_type: Option<TaskType>, status: Option<TaskStatus>) -> Vec<TaskInfo> {
        let tasks = self.tasks.read().await;
        tasks.values()
            .filter(|task| {
                if let Some(ref filter_type) = task_type {
                    if &task.task_type != filter_type {
                        return false;
                    }
                }
                if let Some(ref filter_status) = status {
                    if &task.status != filter_status {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect()
    }

    /// Get active (running or pending) tasks
    pub async fn get_active_tasks(&self) -> Vec<TaskInfo> {
        let tasks = self.tasks.read().await;
        tasks.values()
            .filter(|task| task.is_active())
            .cloned()
            .collect()
    }

    /// Cancel a task by ID
    pub async fn cancel_task(&self, task_id: Uuid) -> Result<(), ApiError> {
        // Update task status
        {
            let mut tasks = self.tasks.write().await;
            if let Some(task) = tasks.get_mut(&task_id) {
                if task.is_active() {
                    task.cancel();
                    tracing::info!("Cancelled task {}", task_id);
                } else {
                    return Err(ApiError::Validation("Task is not active".to_string()));
                }
            } else {
                return Err(ApiError::NotFound("Task not found".to_string()));
            }
        }

        // Abort the task handle if it exists
        {
            let mut handles = self.active_handles.lock().await;
            if let Some(handle) = handles.remove(&task_id) {
                handle.abort();
            }
        }

        Ok(())
    }

    /// Cancel all active tasks
    pub async fn cancel_all_tasks(&self) -> Result<usize, ApiError> {
        let active_task_ids: Vec<Uuid> = {
            let tasks = self.tasks.read().await;
            tasks.values()
                .filter(|task| task.is_active())
                .map(|task| task.id)
                .collect()
        };

        let mut cancelled_count = 0;
        for task_id in active_task_ids {
            if self.cancel_task(task_id).await.is_ok() {
                cancelled_count += 1;
            }
        }

        tracing::info!("Cancelled {} active tasks", cancelled_count);
        Ok(cancelled_count)
    }

    /// Clean up completed tasks older than the specified duration
    pub async fn cleanup_old_tasks(&self, max_age: chrono::Duration) -> Result<usize, ApiError> {
        let cutoff_time = Utc::now() - max_age;
        let mut removed_count = 0;

        {
            let mut tasks = self.tasks.write().await;
            let task_ids_to_remove: Vec<Uuid> = tasks.values()
                .filter(|task| {
                    task.is_finished() && 
                    task.completed_at.map_or(false, |completed| completed < cutoff_time)
                })
                .map(|task| task.id)
                .collect();

            for task_id in task_ids_to_remove {
                tasks.remove(&task_id);
                removed_count += 1;
            }
        }

        if removed_count > 0 {
            tracing::info!("Cleaned up {} old completed tasks", removed_count);
        }

        Ok(removed_count)
    }

    /// Get task manager statistics
    pub async fn get_statistics(&self) -> TaskManagerStats {
        let tasks = self.tasks.read().await;
        let mut stats = TaskManagerStats::default();

        for task in tasks.values() {
            stats.total_tasks += 1;
            match task.status {
                TaskStatus::Pending => stats.pending_tasks += 1,
                TaskStatus::Running => stats.running_tasks += 1,
                TaskStatus::Completed => stats.completed_tasks += 1,
                TaskStatus::Failed => stats.failed_tasks += 1,
                TaskStatus::Cancelled => stats.cancelled_tasks += 1,
            }
        }

        stats.available_slots = self.concurrency_semaphore.available_permits();
        stats.max_concurrent = self.settings.max_concurrent_scans as usize;

        stats
    }

    /// Check if a task is cancelled
    pub async fn is_task_cancelled(&self, task_id: Uuid) -> bool {
        let tasks = self.tasks.read().await;
        tasks.get(&task_id)
            .map(|task| task.status == TaskStatus::Cancelled)
            .unwrap_or(false)
    }

    /// Internal method to start a task
    async fn start_task(&self, task_id: Uuid) -> Result<(), ApiError> {
        let mut tasks = self.tasks.write().await;
        if let Some(task) = tasks.get_mut(&task_id) {
            task.start();
            tracing::info!("Started task {} of type {:?}", task_id, task.task_type);
            Ok(())
        } else {
            Err(ApiError::NotFound("Task not found".to_string()))
        }
    }

    /// Internal method to complete a task
    async fn complete_task(&self, task_id: Uuid) -> Result<(), ApiError> {
        let mut tasks = self.tasks.write().await;
        if let Some(task) = tasks.get_mut(&task_id) {
            task.complete();
            tracing::info!("Completed task {} of type {:?}", task_id, task.task_type);
            Ok(())
        } else {
            Err(ApiError::NotFound("Task not found".to_string()))
        }
    }

    /// Internal method to fail a task
    async fn fail_task(&self, task_id: Uuid, error: String) -> Result<(), ApiError> {
        let mut tasks = self.tasks.write().await;
        if let Some(task) = tasks.get_mut(&task_id) {
            task.fail(error.clone());
            tracing::warn!("Failed task {} of type {:?}: {}", task_id, task.task_type, error);
            Ok(())
        } else {
            Err(ApiError::NotFound("Task not found".to_string()))
        }
    }

    /// Internal method to update task progress
    async fn update_task_progress(&self, task_id: Uuid, progress: f32, message: Option<String>) -> Result<(), ApiError> {
        let mut tasks = self.tasks.write().await;
        if let Some(task) = tasks.get_mut(&task_id) {
            task.update_progress(progress, message);
            Ok(())
        } else {
            Err(ApiError::NotFound("Task not found".to_string()))
        }
    }

    /// Wait for all active tasks to complete (useful for testing and shutdown)
    pub async fn wait_for_all_tasks(&self) -> Result<(), ApiError> {
        loop {
            let active_count = {
                let tasks = self.tasks.read().await;
                tasks.values().filter(|task| task.is_active()).count()
            };

            if active_count == 0 {
                break;
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        Ok(())
    }

    /// Graceful shutdown - cancel all tasks and wait for completion
    pub async fn shutdown(&self) -> Result<(), ApiError> {
        tracing::info!("Shutting down task manager...");
        
        // Cancel all active tasks
        let cancelled_count = self.cancel_all_tasks().await?;
        
        // Wait a bit for tasks to handle cancellation
        if cancelled_count > 0 {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }

        // Abort any remaining handles
        {
            let mut handles = self.active_handles.lock().await;
            for (task_id, handle) in handles.drain() {
                tracing::debug!("Aborting task handle {}", task_id);
                handle.abort();
            }
        }

        tracing::info!("Task manager shutdown complete");
        Ok(())
    }
}

// Implement Clone for TaskManager to enable Arc sharing
impl Clone for TaskManager {
    fn clone(&self) -> Self {
        Self {
            settings: Arc::clone(&self.settings),
            tasks: Arc::clone(&self.tasks),
            active_handles: Arc::clone(&self.active_handles),
            concurrency_semaphore: Arc::clone(&self.concurrency_semaphore),
        }
    }
}

/// Task manager statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskManagerStats {
    pub total_tasks: usize,
    pub pending_tasks: usize,
    pub running_tasks: usize,
    pub completed_tasks: usize,
    pub failed_tasks: usize,
    pub cancelled_tasks: usize,
    pub available_slots: usize,
    pub max_concurrent: usize,
}

impl Default for TaskManagerStats {
    fn default() -> Self {
        Self {
            total_tasks: 0,
            pending_tasks: 0,
            running_tasks: 0,
            completed_tasks: 0,
            failed_tasks: 0,
            cancelled_tasks: 0,
            available_slots: 0,
            max_concurrent: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;

    async fn create_test_task_manager() -> TaskManager {
        let mut settings = crate::config::Settings::new_with_env_file(false).unwrap();
        settings.max_concurrent_scans = 2; // Small limit for testing
        TaskManager::new(Arc::new(settings))
    }

    #[tokio::test]
    async fn test_task_creation_and_execution() {
        let task_manager = create_test_task_manager().await;
        
        let task_id = task_manager.submit_task(
            TaskType::Scan,
            serde_json::json!({"test": "data"}),
            |_ctx| Box::pin(async {
                sleep(Duration::from_millis(100)).await;
                Ok(())
            })
        ).await.unwrap();

        // Task should initially be pending
        let task = task_manager.get_task(task_id).await.unwrap();
        assert_eq!(task.status, TaskStatus::Pending);

        // Wait for task to complete
        sleep(Duration::from_millis(200)).await;

        let task = task_manager.get_task(task_id).await.unwrap();
        assert_eq!(task.status, TaskStatus::Completed);
        assert_eq!(task.progress, 1.0);
    }

    #[tokio::test]
    async fn test_task_failure() {
        let task_manager = create_test_task_manager().await;
        
        let task_id = task_manager.submit_task(
            TaskType::Scan,
            serde_json::json!({}),
            |_ctx| Box::pin(async {
                Err(ApiError::Validation("Test error".to_string()))
            })
        ).await.unwrap();

        // Wait for task to fail
        sleep(Duration::from_millis(100)).await;

        let task = task_manager.get_task(task_id).await.unwrap();
        assert_eq!(task.status, TaskStatus::Failed);
        assert!(task.error.is_some());
        assert!(task.error.unwrap().contains("Test error"));
    }

    #[tokio::test]
    async fn test_task_cancellation() {
        let task_manager = create_test_task_manager().await;
        
        let task_id = task_manager.submit_task(
            TaskType::Scan,
            serde_json::json!({}),
            |ctx| Box::pin(async move {
                for i in 0..10 {
                    ctx.check_cancellation().await?;
                    ctx.update_progress(i as f32 / 10.0, Some(format!("Step {}", i))).await?;
                    sleep(Duration::from_millis(50)).await;
                }
                Ok(())
            })
        ).await.unwrap();

        // Let task start
        sleep(Duration::from_millis(25)).await;

        // Cancel the task
        task_manager.cancel_task(task_id).await.unwrap();

        // Wait a bit
        sleep(Duration::from_millis(100)).await;

        let task = task_manager.get_task(task_id).await.unwrap();
        assert_eq!(task.status, TaskStatus::Cancelled);
    }

    #[tokio::test]
    async fn test_concurrency_limits() {
        let task_manager = create_test_task_manager().await;
        
        // Submit 4 tasks (more than the limit of 2)
        let mut task_ids = Vec::new();
        for i in 0..4 {
            let task_id = task_manager.submit_task(
                TaskType::Scan,
                serde_json::json!({"task": i}),
                |_ctx| Box::pin(async {
                    sleep(Duration::from_millis(200)).await;
                    Ok(())
                })
            ).await.unwrap();
            task_ids.push(task_id);
        }

        // Check that only 2 tasks are running initially
        sleep(Duration::from_millis(50)).await;
        let active_tasks = task_manager.get_active_tasks().await;
        let running_count = active_tasks.iter().filter(|t| t.status == TaskStatus::Running).count();
        assert!(running_count <= 2);

        // Wait for all tasks to complete
        sleep(Duration::from_millis(500)).await;

        // All tasks should be completed
        for task_id in task_ids {
            let task = task_manager.get_task(task_id).await.unwrap();
            assert_eq!(task.status, TaskStatus::Completed);
        }
    }

    #[tokio::test]
    async fn test_task_progress_updates() {
        let task_manager = create_test_task_manager().await;
        
        let task_id = task_manager.submit_task(
            TaskType::Scan,
            serde_json::json!({}),
            |ctx| Box::pin(async move {
                for i in 0..5 {
                    let progress = i as f32 / 4.0;
                    ctx.update_progress(progress, Some(format!("Step {}", i + 1))).await?;
                    sleep(Duration::from_millis(50)).await;
                }
                Ok(())
            })
        ).await.unwrap();

        // Wait for some progress
        sleep(Duration::from_millis(125)).await;

        let task = task_manager.get_task(task_id).await.unwrap();
        assert!(task.progress > 0.0);
        assert!(task.message.is_some());

        // Wait for completion
        sleep(Duration::from_millis(200)).await;

        let task = task_manager.get_task(task_id).await.unwrap();
        assert_eq!(task.status, TaskStatus::Completed);
        assert_eq!(task.progress, 1.0);
    }

    #[tokio::test]
    async fn test_task_listing_and_filtering() {
        let task_manager = create_test_task_manager().await;
        
        // Submit different types of tasks
        let _scan_task = task_manager.submit_task(
            TaskType::Scan,
            serde_json::json!({}),
            |_ctx| Box::pin(async { Ok(()) })
        ).await.unwrap();

        let _discovery_task = task_manager.submit_task(
            TaskType::Discovery,
            serde_json::json!({}),
            |_ctx| Box::pin(async { Ok(()) })
        ).await.unwrap();

        // Wait for tasks to complete
        sleep(Duration::from_millis(100)).await;

        // Test listing all tasks
        let all_tasks = task_manager.list_tasks(None, None).await;
        assert_eq!(all_tasks.len(), 2);

        // Test filtering by type
        let scan_tasks = task_manager.list_tasks(Some(TaskType::Scan), None).await;
        assert_eq!(scan_tasks.len(), 1);
        assert_eq!(scan_tasks[0].task_type, TaskType::Scan);

        let discovery_tasks = task_manager.list_tasks(Some(TaskType::Discovery), None).await;
        assert_eq!(discovery_tasks.len(), 1);
        assert_eq!(discovery_tasks[0].task_type, TaskType::Discovery);

        // Test filtering by status
        let completed_tasks = task_manager.list_tasks(None, Some(TaskStatus::Completed)).await;
        assert_eq!(completed_tasks.len(), 2);
    }

    #[tokio::test]
    async fn test_task_cleanup() {
        let task_manager = create_test_task_manager().await;
        
        // Submit and complete a task
        let _task_id = task_manager.submit_task(
            TaskType::Scan,
            serde_json::json!({}),
            |_ctx| Box::pin(async { Ok(()) })
        ).await.unwrap();

        // Wait for completion
        sleep(Duration::from_millis(100)).await;

        // Verify task exists
        let all_tasks = task_manager.list_tasks(None, None).await;
        assert_eq!(all_tasks.len(), 1);

        // Clean up tasks older than 0 seconds (should remove the completed task)
        let removed_count = task_manager.cleanup_old_tasks(chrono::Duration::seconds(0)).await.unwrap();
        assert_eq!(removed_count, 1);

        // Verify task was removed
        let all_tasks = task_manager.list_tasks(None, None).await;
        assert_eq!(all_tasks.len(), 0);
    }

    #[tokio::test]
    async fn test_task_statistics() {
        let task_manager = create_test_task_manager().await;
        
        // Submit tasks with different outcomes
        let _completed_task = task_manager.submit_task(
            TaskType::Scan,
            serde_json::json!({}),
            |_ctx| Box::pin(async { Ok(()) })
        ).await.unwrap();

        let _failed_task = task_manager.submit_task(
            TaskType::Discovery,
            serde_json::json!({}),
            |_ctx| Box::pin(async { Err(ApiError::Validation("Test error".to_string())) })
        ).await.unwrap();

        let cancelled_task = task_manager.submit_task(
            TaskType::AssetProcessing,
            serde_json::json!({}),
            |_ctx| Box::pin(async {
                sleep(Duration::from_millis(1000)).await;
                Ok(())
            })
        ).await.unwrap();

        // Wait for some tasks to process
        sleep(Duration::from_millis(50)).await;

        // Cancel one task
        task_manager.cancel_task(cancelled_task).await.unwrap();

        // Wait for completion
        sleep(Duration::from_millis(100)).await;

        let stats = task_manager.get_statistics().await;
        assert_eq!(stats.total_tasks, 3);
        assert_eq!(stats.completed_tasks, 1);
        assert_eq!(stats.failed_tasks, 1);
        assert_eq!(stats.cancelled_tasks, 1);
        assert_eq!(stats.max_concurrent, 2);
    }
}