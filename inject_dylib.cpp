#include <mach/mach.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/types.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>

// Configuration for anogs framework targeting
struct InjectionConfig {
    const char* target_dylib = "anogs.framework/anogs";
    const char* hook_dylib_path = NULL;  // Set at runtime
    int retry_count = 3;
    int retry_delay_ms = 100;
};

class DyldInjector {
private:
    task_t target_task;
    InjectionConfig config;

    // DYLD_INSERT_LIBRARIES injection via environment
    bool InjectViaEnvironment(pid_t pid, const char* dylib_path) {
        char env_var[512];
        snprintf(env_var, sizeof(env_var), "DYLD_INSERT_LIBRARIES=%s", dylib_path);
        
        // This approach requires the target process to be launched with the env var set
        // Use this when you can control process spawn
        setenv("DYLD_INSERT_LIBRARIES", dylib_path, 1);
        return true;
    }

    // Direct mach-port based injection (more reliable)
    bool InjectViaRPC(pid_t target_pid, const char* dylib_path) {
        kern_return_t kr;
        task_t target_task;
        mach_port_t remote_thread;
        
        // Get task port for target process
        kr = task_for_pid(mach_task_self(), target_pid, &target_task);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "task_for_pid failed: %d\n", kr);
            return false;
        }

        // Allocate memory in target process for dylib path string
        mach_vm_address_t remote_str = 0;
        mach_vm_size_t str_size = strlen(dylib_path) + 1;
        
        kr = mach_vm_allocate(target_task, &remote_str, str_size, VM_FLAGS_ANYWHERE);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "mach_vm_allocate failed: %d\n", kr);
            mach_port_deallocate(mach_task_self(), target_task);
            return false;
        }

        // Write dylib path to remote memory
        kr = mach_vm_write(target_task, remote_str, (vm_offset_t)dylib_path, str_size);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "mach_vm_write failed: %d\n", kr);
            mach_vm_deallocate(target_task, remote_str, str_size);
            mach_port_deallocate(mach_task_self(), target_task);
            return false;
        }

        // Get dlopen address in target process
        // dlopen is loaded in every process at the same relative offset from dyld
        uint64_t dlopen_addr = (uint64_t)dlopen;

        // Allocate stack space for remote thread
        mach_vm_address_t remote_stack = 0;
        mach_vm_size_t stack_size = 0x4000;
        kr = mach_vm_allocate(target_task, &remote_stack, stack_size, VM_FLAGS_ANYWHERE);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "mach_vm_allocate stack failed: %d\n", kr);
            mach_vm_deallocate(target_task, remote_str, str_size);
            mach_port_deallocate(mach_task_self(), target_task);
            return false;
        }

        // ARM64 calling convention:
        // x0 = first arg (dylib path pointer)
        // x1 = second arg (flags = RTLD_NOW)
        // sp points to stack
        // lr (x30) points to return address

        arm_thread_state64_t thread_state = {};
        thread_state.__pc = dlopen_addr;  // Program counter = dlopen
        thread_state.__sp = remote_stack + stack_size - 8;  // Stack pointer
        thread_state.__x[0] = remote_str;  // x0 = dylib path
        thread_state.__x[1] = 0x00000002;  // x1 = RTLD_NOW | RTLD_LOCAL
        thread_state.__x[30] = 0;  // x30 = return address (0 will cause thread exit)

        // Create remote thread
        kr = thread_create_running(target_task, ARM_THREAD_STATE64,
                                   (thread_state_t)&thread_state,
                                   ARM_THREAD_STATE64_COUNT,
                                   &remote_thread);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "thread_create_running failed: %d\n", kr);
            mach_vm_deallocate(target_task, remote_stack, stack_size);
            mach_vm_deallocate(target_task, remote_str, str_size);
            mach_port_deallocate(mach_task_self(), target_task);
            return false;
        }

        // Wait for thread to complete
        thread_join(remote_thread);
        thread_terminate(remote_thread);
        mach_port_deallocate(mach_task_self(), remote_thread);

        // Cleanup
        mach_vm_deallocate(target_task, remote_stack, stack_size);
        mach_vm_deallocate(target_task, remote_str, str_size);
        mach_port_deallocate(mach_task_self(), target_task);

        return true;
    }

public:
    DyldInjector() : target_task(mach_task_self()) {}

    bool SetTargetProcess(pid_t pid) {
        kern_return_t kr = task_for_pid(mach_task_self(), pid, &target_task);
        return kr == KERN_SUCCESS;
    }

    bool InjectDylib(const char* dylib_path) {
        // Try environment variable injection first (simpler)
        if (InjectViaEnvironment(0, dylib_path)) {
            return true;
        }

        // Fallback to RPC injection if available
        return InjectViaRPC(getpid(), dylib_path);
    }

    // Direct hooking for current process
    bool InjectLocal(const char* dylib_path) {
        void* handle = dlopen(dylib_path, RTLD_NOW | RTLD_LOCAL);
        if (!handle) {
            fprintf(stderr, "dlopen failed: %s\n", dlerror());
            return false;
        }
        
        // dlopen automatically runs the constructor which installs hooks
        return true;
    }
};

// Hook installation with retry logic
class HookInstaller {
private:
    DyldInjector injector;
    InjectionConfig config;

public:
    HookInstaller(const InjectionConfig& cfg) : config(cfg) {}

    bool Install(const char* hook_dylib_path) {
        config.hook_dylib_path = hook_dylib_path;

        for (int attempt = 0; attempt < config.retry_count; ++attempt) {
            if (injector.InjectLocal(hook_dylib_path)) {
                fprintf(stderr, "[+] Hook installed successfully\n");
                return true;
            }

            fprintf(stderr, "[!] Injection attempt %d failed, retrying...\n", attempt + 1);
            usleep(config.retry_delay_ms * 1000);
        }

        return false;
    }

    bool InstallRemote(pid_t target_pid, const char* hook_dylib_path) {
        config.hook_dylib_path = hook_dylib_path;

        if (!injector.SetTargetProcess(target_pid)) {
            fprintf(stderr, "[-] Failed to get task port for PID %d\n", target_pid);
            return false;
        }

        for (int attempt = 0; attempt < config.retry_count; ++attempt) {
            if (injector.InjectDylib(hook_dylib_path)) {
                fprintf(stderr, "[+] Remote hook installed successfully\n");
                return true;
            }

            fprintf(stderr, "[!] Remote injection attempt %d failed, retrying...\n", attempt + 1);
            usleep(config.retry_delay_ms * 1000);
        }

        return false;
    }
};

// Export for external use
extern "C" {
    int InstallAnogsHook(const char* dylib_path) {
        InjectionConfig config;
        HookInstaller installer(config);
        return installer.Install(dylib_path) ? 0 : -1;
    }

    int InstallAnogsHookRemote(pid_t target_pid, const char* dylib_path) {
        InjectionConfig config;
        HookInstaller installer(config);
        return installer.InstallRemote(target_pid, dylib_path) ? 0 : -1;
    }
}

// Standalone loader (compile with -e main)
int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <path_to_hook_dylib> [target_pid]\n", argv[0]);
        return 1;
    }

    const char* hook_path = argv[1];
    InjectionConfig config;
    HookInstaller installer(config);

    if (argc == 3) {
        pid_t target_pid = atoi(argv[2]);
        fprintf(stderr, "[*] Installing hook into PID %d\n", target_pid);
        return installer.InstallRemote(target_pid, hook_path) ? 0 : 1;
    } else {
        fprintf(stderr, "[*] Installing hook into current process\n");
        return installer.Install(hook_path) ? 0 : 1;
    }
}
