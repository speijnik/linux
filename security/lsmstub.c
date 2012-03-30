/*
 * LSMStub - support for loadable security modules in development environments.
 *
 * Copyright (C) 2012 Stephan Peijnik <stephan@peijnik.at>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	Due to this file being licensed under the GPL there is controversy over
 *	whether this permits you to write a module that #includes this file
 *	without placing your module under the GPL.  Please consult a lawyer for
 *	advice before doing this.
 *
 * WARNING: (AGAIN) DO NOT USE IN PRODUCTION ENVIRONMENTS.
 * It is generally undesired behaviour for a LSM module to be unloadable
 * in production systems.
 * LSMStub exists for the sole purpose of developing LSM modules ONLY, so one
 * does not have to re-compile the kernel and reboot every time one makes
 * a change to the LSMs code. 
 */

#include <linux/module.h>
#include <linux/security.h>
#include <linux/rwlock.h>
#include <linux/lsmstub.h>

static struct security_operations* lsmstub_mod_ops = NULL;
static struct security_operations lsmstub_null_ops = {
  .name = "none",
};
static struct module* lsmstub_mod = NULL;
static unsigned int lsmstub_registered = 0;
static unsigned int lsmstub_mod_registered = 0;
static struct dentry* lsmstub_fs_dentry = NULL;
static struct dentry* lsmstub_lsm_dentry = NULL;

static DEFINE_RWLOCK(lsmstub_ops_rwlock);

#define __LSM_STUB_HEADER(NAME)				\
  read_lock_irqsave(&lsmstub_ops_rwlock, lk_flags);	\
  if (lsmstub_mod == NULL ||				\
      lsmstub_mod_ops == NULL)	{			\
    read_unlock_irqrestore(&lsmstub_ops_rwlock,		\
			   lk_flags);			\
    goto out;						\
  }							\
  if (!try_module_get(lsmstub_mod)) {			\
    read_unlock_irqrestore(&lsmstub_ops_rwlock,		\
			   lk_flags);			\
    goto out;						\
  }							\
  func = lsmstub_mod_ops-> NAME;			\
  read_unlock_irqrestore(&lsmstub_ops_rwlock,		\
			 lk_flags);			\
  
#define __LSM_STUB_FOOTER()			\
  module_put(lsmstub_mod)

#define LSM_STUB_FUNC_NAME(NAME)		\
  stub_ ##NAME

#define LSM_STUB_FUNC(NAME, SIGNATURE, ...)		\
  static int LSM_STUB_FUNC_NAME(NAME) SIGNATURE {	\
    int res = 0;					\
    unsigned long lk_flags;				\
    int (*func) SIGNATURE;				\
    if (!lsmstub_mod_registered)			\
      return lsmstub_null_ops. NAME(__VA_ARGS__);	\
    __LSM_STUB_HEADER(NAME);				\
    if (func != NULL) {					\
      res = func(__VA_ARGS__);				\
    }							\
    __LSM_STUB_FOOTER();				\
  out:							\
    return res;						\
  }
  
#define LSM_STUB_FUNC_VOID(NAME, SIGNATURE, ...)	\
  static void LSM_STUB_FUNC_NAME(NAME) SIGNATURE {	\
    unsigned long lk_flags;				\
    void (*func) SIGNATURE;				\
    if (!lsmstub_mod_registered) {	 		\
      lsmstub_null_ops. NAME (__VA_ARGS__);		\
      return;						\
    }							\
    __LSM_STUB_HEADER(NAME);				\
    if (func != NULL) {					\
      func(__VA_ARGS__);				\
    }							\
    __LSM_STUB_FOOTER();				\
  out:							\
    return;						\
  }

LSM_STUB_FUNC(ptrace_access_check, (struct task_struct* child,  unsigned int mode), child, mode);
LSM_STUB_FUNC(ptrace_traceme, (struct task_struct* parent), parent);
LSM_STUB_FUNC(capget, (struct task_struct* target, kernel_cap_t* effective, kernel_cap_t* inheritable,  kernel_cap_t* permitted), target, effective, inheritable, permitted);
LSM_STUB_FUNC(capset, (struct cred* new, const struct cred* old, const kernel_cap_t* effective, const kernel_cap_t* inheritable, const kernel_cap_t* permitted), new, old, effective, inheritable, permitted);
LSM_STUB_FUNC(capable, (const struct cred* cred,  struct user_namespace* ns, int cap,  int audit), cred, ns, cap, audit);
LSM_STUB_FUNC(quotactl, (int cmds,  int type,  int id,  struct super_block* sb), cmds, type, id, sb);
LSM_STUB_FUNC(quota_on, (struct dentry* dentry), dentry);
LSM_STUB_FUNC(syslog, (int type), type);
LSM_STUB_FUNC(settime, (const struct timespec* ts,  const struct timezone* tz), ts, tz);
LSM_STUB_FUNC(vm_enough_memory, (struct mm_struct* mm,  long pages), mm, pages);
LSM_STUB_FUNC(bprm_set_creds, (struct linux_binprm* bprm), bprm);
LSM_STUB_FUNC(bprm_check_security, (struct linux_binprm* bprm), bprm);
LSM_STUB_FUNC(bprm_secureexec, (struct linux_binprm* bprm), bprm);
LSM_STUB_FUNC_VOID(bprm_committing_creds, (struct linux_binprm* bprm), bprm);
LSM_STUB_FUNC_VOID(bprm_committed_creds, (struct linux_binprm* bprm), bprm);
LSM_STUB_FUNC(sb_alloc_security, (struct super_block* sb), sb);
LSM_STUB_FUNC_VOID(sb_free_security, (struct super_block* sb), sb);
LSM_STUB_FUNC(sb_copy_data, (char* orig,  char* copy), orig, copy);
LSM_STUB_FUNC(sb_remount, (struct super_block* sb,  void* data), sb, data);
LSM_STUB_FUNC(sb_kern_mount, (struct super_block* sb,  int flags,  void* data), sb, flags, data);
LSM_STUB_FUNC(sb_show_options, (struct seq_file* m,  struct super_block* sb), m, sb);
LSM_STUB_FUNC(sb_statfs, (struct dentry* dentry), dentry);
LSM_STUB_FUNC(sb_mount, (char* dev_name,  struct path* path, char* type,  unsigned long flags,  void* data), dev_name, path, type, flags, data);
LSM_STUB_FUNC(sb_umount, (struct vfsmount* mnt,  int flags), mnt, flags);
LSM_STUB_FUNC(sb_pivotroot, (struct path* old_path, struct path* new_path), old_path, new_path);
LSM_STUB_FUNC(sb_set_mnt_opts, (struct super_block* sb, struct security_mnt_opts* opts), sb, opts);
LSM_STUB_FUNC_VOID(sb_clone_mnt_opts, (const struct super_block* oldsb, struct super_block* newsb), oldsb, newsb);
LSM_STUB_FUNC(sb_parse_opts_str, (char* options,  struct security_mnt_opts* opts), options, opts);
#ifdef CONFIG_SECURITY_PATH
LSM_STUB_FUNC(path_unlink, (struct path* dir,  struct dentry* dentry), dir, dentry);
LSM_STUB_FUNC(path_mkdir, (struct path* dir,  struct dentry* dentry, umode_t mode), dir, dentry, mode);
LSM_STUB_FUNC(path_rmdir, (struct path* dir,  struct dentry* dentry), dir, dentry);
LSM_STUB_FUNC(path_mknod, (struct path* dir,  struct dentry* dentry, umode_t mode, unsigned int dev), dir, dentry, mode, dev);
LSM_STUB_FUNC(path_truncate, (struct path* path), path);
LSM_STUB_FUNC(path_symlink, (struct path* dir,  struct dentry* dentry, const char* old_name), dir, dentry, old_name);
LSM_STUB_FUNC(path_link, (struct dentry* old_dentry,  struct path* new_dir, struct dentry* new_dentry), old_dentry, new_dir, new_dentry);
LSM_STUB_FUNC(path_rename, (struct path* old_dir,  struct dentry* old_dentry, struct path* new_dir,  struct dentry* new_dentry), old_dir, old_dentry, new_dir, new_dentry);
LSM_STUB_FUNC(path_chmod, (struct path* path, umode_t mode), path, mode);
LSM_STUB_FUNC(path_chown, (struct path* path,  uid_t uid,  gid_t gid), path, uid, gid);
LSM_STUB_FUNC(path_chroot, (struct path* path), path);
#endif
LSM_STUB_FUNC(inode_alloc_security, (struct inode* inode), inode);
LSM_STUB_FUNC_VOID(inode_free_security, (struct inode* inode), inode);
LSM_STUB_FUNC(inode_init_security, (struct inode* inode,  struct inode* dir, const struct qstr* qstr,  char** name, void** value,  size_t* len), inode, dir, qstr, name, value, len);
LSM_STUB_FUNC(inode_create, (struct inode* dir, struct dentry* dentry, int mode), dir, dentry, mode);
LSM_STUB_FUNC(inode_link, (struct dentry* old_dentry, struct inode* dir,  struct dentry* new_dentry), old_dentry, dir, new_dentry);
LSM_STUB_FUNC(inode_unlink, (struct inode* dir,  struct dentry* dentry), dir, dentry);
LSM_STUB_FUNC(inode_symlink, (struct inode* dir, struct dentry* dentry,  const char* old_name), dir, dentry, old_name);
LSM_STUB_FUNC(inode_mkdir, (struct inode* dir,  struct dentry* dentry, int mode), dir, dentry, mode);
LSM_STUB_FUNC(inode_rmdir, (struct inode* dir,  struct dentry* dentry), dir, dentry);
LSM_STUB_FUNC(inode_mknod, (struct inode* dir,  struct dentry* dentry, int mode,  dev_t dev), dir, dentry, mode, dev);
LSM_STUB_FUNC(inode_rename, (struct inode* old_dir,  struct dentry* old_dentry, struct inode* new_dir,  struct dentry* new_dentry), old_dir, old_dentry, new_dir, new_dentry);
LSM_STUB_FUNC(inode_readlink, (struct dentry* dentry), dentry);
LSM_STUB_FUNC(inode_follow_link, (struct dentry* dentry,  struct nameidata* nd), dentry, nd);
LSM_STUB_FUNC(inode_permission, (struct inode* inode,  int mask), inode, mask);
LSM_STUB_FUNC(inode_setattr, (struct dentry* dentry,  struct iattr* attr), dentry, attr);
LSM_STUB_FUNC(inode_getattr, (struct vfsmount* mnt,  struct dentry* dentry), mnt, dentry);
LSM_STUB_FUNC(inode_setxattr, (struct dentry* dentry,  const char* name, const void* value,  size_t size,  int flags), dentry, name, value, size, flags);
LSM_STUB_FUNC_VOID(inode_post_setxattr, (struct dentry* dentry,  const char* name, const void* value,  size_t size,  int flags), dentry, name, value, size, flags);
LSM_STUB_FUNC(inode_getxattr, (struct dentry* dentry,  const char* name), dentry, name);
LSM_STUB_FUNC(inode_listxattr, (struct dentry* dentry), dentry);
LSM_STUB_FUNC(inode_removexattr, (struct dentry* dentry,  const char* name), dentry, name);
LSM_STUB_FUNC(inode_need_killpriv, (struct dentry* dentry), dentry);
LSM_STUB_FUNC(inode_killpriv, (struct dentry* dentry), dentry);
LSM_STUB_FUNC(inode_getsecurity, (const struct inode* inode,  const char* name,  void** buffer,  bool alloc), inode, name, buffer, alloc);
LSM_STUB_FUNC(inode_setsecurity, (struct inode* inode,  const char* name,  const void* value,  size_t size,  int flags), inode, name, value, size, flags);
LSM_STUB_FUNC(inode_listsecurity, (struct inode* inode,  char* buffer,  size_t buffer_size), inode, buffer, buffer_size);
LSM_STUB_FUNC_VOID(inode_getsecid, (const struct inode* inode,  u32* secid), inode, secid);
LSM_STUB_FUNC(file_permission, (struct file* file,  int mask), file, mask);
LSM_STUB_FUNC(file_alloc_security, (struct file* file), file);
LSM_STUB_FUNC_VOID(file_free_security, (struct file* file), file);
LSM_STUB_FUNC(file_ioctl, (struct file* file,  unsigned int cmd, unsigned long arg), file, cmd, arg);
LSM_STUB_FUNC(file_mmap, (struct file* file, unsigned long reqprot,  unsigned long prot, unsigned long flags,  unsigned long addr, unsigned long addr_only), file, reqprot, prot, flags, addr, addr_only);
LSM_STUB_FUNC(file_mprotect, (struct vm_area_struct* vma, unsigned long reqprot, unsigned long prot), vma, reqprot, prot);
LSM_STUB_FUNC(file_lock, (struct file* file,  unsigned int cmd), file, cmd);
LSM_STUB_FUNC(file_fcntl, (struct file* file,  unsigned int cmd, unsigned long arg), file, cmd, arg);
LSM_STUB_FUNC(file_set_fowner, (struct file* file), file);
LSM_STUB_FUNC(file_send_sigiotask, (struct task_struct* tsk, struct fown_struct* fown,  int sig), tsk, fown, sig);
LSM_STUB_FUNC(file_receive, (struct file* file), file);
LSM_STUB_FUNC(dentry_open, (struct file* file,  const struct cred* cred), file, cred);
LSM_STUB_FUNC(task_create, (unsigned long clone_flags), clone_flags);
LSM_STUB_FUNC(cred_alloc_blank, (struct cred* cred,  gfp_t gfp), cred, gfp);
LSM_STUB_FUNC_VOID(cred_free, (struct cred* cred), cred);
LSM_STUB_FUNC(cred_prepare, (struct cred *new, const struct cred *old,
			     gfp_t gfp), new, old, gfp);
LSM_STUB_FUNC_VOID(cred_transfer, (struct cred* new,  const struct cred* old), new, old);
LSM_STUB_FUNC(kernel_act_as, (struct cred* new,  u32 secid), new, secid);
LSM_STUB_FUNC(kernel_create_files_as, (struct cred* new,  struct inode* inode), new, inode);
LSM_STUB_FUNC(kernel_module_request, (char* kmod_name), kmod_name);
LSM_STUB_FUNC(task_fix_setuid, (struct cred* new,  const struct cred* old, int flags), new, old, flags);
LSM_STUB_FUNC(task_setpgid, (struct task_struct* p,  pid_t pgid), p, pgid);
LSM_STUB_FUNC(task_getpgid, (struct task_struct* p), p);
LSM_STUB_FUNC(task_getsid, (struct task_struct* p), p);
LSM_STUB_FUNC_VOID(task_getsecid, (struct task_struct* p,  u32* secid), p, secid);
LSM_STUB_FUNC(task_setnice, (struct task_struct* p,  int nice), p, nice);
LSM_STUB_FUNC(task_setioprio, (struct task_struct* p,  int ioprio), p, ioprio);
LSM_STUB_FUNC(task_getioprio, (struct task_struct* p), p);
LSM_STUB_FUNC(task_setrlimit, (struct task_struct* p,  unsigned int resource, struct rlimit* new_rlim), p, resource, new_rlim);
LSM_STUB_FUNC(task_setscheduler, (struct task_struct* p), p);
LSM_STUB_FUNC(task_getscheduler, (struct task_struct* p), p);
LSM_STUB_FUNC(task_movememory, (struct task_struct* p), p);
LSM_STUB_FUNC(task_kill, (struct task_struct* p, struct siginfo* info,  int sig,  u32 secid), p, info, sig, secid);
LSM_STUB_FUNC(task_wait, (struct task_struct* p), p);
LSM_STUB_FUNC(task_prctl, (int option,  unsigned long arg2, unsigned long arg3,  unsigned long arg4, unsigned long arg5), option, arg2, arg3, arg4, arg5);
LSM_STUB_FUNC_VOID(task_to_inode, (struct task_struct* p,  struct inode* inode), p, inode);
LSM_STUB_FUNC(ipc_permission, (struct kern_ipc_perm* ipcp,  short flag), ipcp, flag);
LSM_STUB_FUNC_VOID(ipc_getsecid, (struct kern_ipc_perm* ipcp,  u32* secid), ipcp, secid);
LSM_STUB_FUNC(msg_msg_alloc_security, (struct msg_msg* msg), msg);
LSM_STUB_FUNC_VOID(msg_msg_free_security, (struct msg_msg* msg), msg);
LSM_STUB_FUNC(msg_queue_alloc_security, (struct msg_queue* msq), msq);
LSM_STUB_FUNC_VOID(msg_queue_free_security, (struct msg_queue* msq), msq);
LSM_STUB_FUNC(msg_queue_associate, (struct msg_queue* msq,  int msqflg), msq, msqflg);
LSM_STUB_FUNC(msg_queue_msgctl, (struct msg_queue* msq,  int cmd), msq, cmd);
LSM_STUB_FUNC(msg_queue_msgsnd, (struct msg_queue* msq, struct msg_msg* msg,  int msqflg), msq, msg, msqflg);
LSM_STUB_FUNC(msg_queue_msgrcv, (struct msg_queue* msq, struct msg_msg* msg, struct task_struct* target, long type,  int mode), msq, msg, target, type, mode);
LSM_STUB_FUNC(shm_alloc_security, (struct shmid_kernel* shp), shp);
LSM_STUB_FUNC_VOID(shm_free_security, (struct shmid_kernel* shp), shp);
LSM_STUB_FUNC(shm_associate, (struct shmid_kernel* shp,  int shmflg), shp, shmflg);
LSM_STUB_FUNC(shm_shmctl, (struct shmid_kernel* shp,  int cmd), shp, cmd);
LSM_STUB_FUNC(shm_shmat, (struct shmid_kernel* shp, char __user* shmaddr,  int shmflg), shp, shmaddr, shmflg);
LSM_STUB_FUNC(sem_alloc_security, (struct sem_array* sma), sma);
LSM_STUB_FUNC_VOID(sem_free_security, (struct sem_array* sma), sma);
LSM_STUB_FUNC(sem_associate, (struct sem_array* sma,  int semflg), sma, semflg);
LSM_STUB_FUNC(sem_semctl, (struct sem_array* sma,  int cmd), sma, cmd);
LSM_STUB_FUNC(sem_semop, (struct sem_array* sma, struct sembuf* sops,  unsigned nsops,  int alter), sma, sops, nsops, alter);
LSM_STUB_FUNC(netlink_send, (struct sock* sk,  struct sk_buff* skb), sk, skb);
LSM_STUB_FUNC_VOID(d_instantiate, (struct dentry* dentry,  struct inode* inode), dentry, inode);
LSM_STUB_FUNC(getprocattr, (struct task_struct* p,  char* name,  char** value), p, name, value);
LSM_STUB_FUNC(setprocattr, (struct task_struct* p,  char* name,  void* value,  size_t size), p, name, value, size);
LSM_STUB_FUNC(secid_to_secctx, (u32 secid,  char** secdata,  u32* seclen), secid, secdata, seclen);
LSM_STUB_FUNC(secctx_to_secid, (const char* secdata,  u32 seclen,  u32* secid), secdata, seclen, secid);
LSM_STUB_FUNC_VOID(release_secctx, (char* secdata,  u32 seclen), secdata, seclen);
LSM_STUB_FUNC(inode_notifysecctx, (struct inode* inode,  void* ctx,  u32 ctxlen), inode, ctx, ctxlen);
LSM_STUB_FUNC(inode_setsecctx, (struct dentry* dentry,  void* ctx,  u32 ctxlen), dentry, ctx, ctxlen);
LSM_STUB_FUNC(inode_getsecctx, (struct inode* inode,  void** ctx,  u32* ctxlen), inode, ctx, ctxlen);
#ifdef CONFIG_SECURITY_NETWORK
LSM_STUB_FUNC(unix_stream_connect, (struct sock* sock,  struct sock* other,  struct sock* newsk), sock, other, newsk);
LSM_STUB_FUNC(unix_may_send, (struct socket* sock,  struct socket* other), sock, other);
LSM_STUB_FUNC(socket_create, (int family,  int type,  int protocol,  int kern), family, type, protocol, kern);
LSM_STUB_FUNC(socket_post_create, (struct socket* sock,  int family, int type,  int protocol,  int kern), sock, family, type, protocol, kern);
LSM_STUB_FUNC(socket_bind, (struct socket* sock, struct sockaddr* address,  int addrlen), sock, address, addrlen);
LSM_STUB_FUNC(socket_connect, (struct socket* sock, struct sockaddr* address,  int addrlen), sock, address, addrlen);
LSM_STUB_FUNC(socket_listen, (struct socket* sock,  int backlog), sock, backlog);
LSM_STUB_FUNC(socket_accept, (struct socket* sock,  struct socket* newsock), sock, newsock);
LSM_STUB_FUNC(socket_sendmsg, (struct socket* sock, struct msghdr* msg,  int size), sock, msg, size);
LSM_STUB_FUNC(socket_recvmsg, (struct socket* sock, struct msghdr* msg,  int size,  int flags), sock, msg, size, flags);
LSM_STUB_FUNC(socket_getsockname, (struct socket* sock), sock);
LSM_STUB_FUNC(socket_getpeername, (struct socket* sock), sock);
LSM_STUB_FUNC(socket_getsockopt, (struct socket* sock,  int level,  int optname), sock, level, optname);
LSM_STUB_FUNC(socket_setsockopt, (struct socket* sock,  int level,  int optname), sock, level, optname);
LSM_STUB_FUNC(socket_shutdown, (struct socket* sock,  int how), sock, how);
LSM_STUB_FUNC(socket_sock_rcv_skb, (struct sock* sk,  struct sk_buff* skb), sk, skb);
LSM_STUB_FUNC(socket_getpeersec_stream, (struct socket* sock,  char __user* optval,  int __user* optlen,  unsigned len), sock, optval, optlen, len);
LSM_STUB_FUNC(socket_getpeersec_dgram, (struct socket* sock,  struct sk_buff* skb,  u32* secid), sock, skb, secid);
LSM_STUB_FUNC(sk_alloc_security, (struct sock* sk,  int family,  gfp_t priority), sk, family, priority);
LSM_STUB_FUNC_VOID(sk_free_security, (struct sock* sk), sk);
LSM_STUB_FUNC_VOID(sk_clone_security, (const struct sock* sk,  struct sock* newsk), sk, newsk);
LSM_STUB_FUNC_VOID(sk_getsecid, (struct sock* sk,  u32* secid), sk, secid);
LSM_STUB_FUNC_VOID(sock_graft, (struct sock* sk,  struct socket* parent), sk, parent);
LSM_STUB_FUNC(inet_conn_request, (struct sock* sk,  struct sk_buff* skb, struct request_sock* req), sk, skb, req);
LSM_STUB_FUNC_VOID(inet_csk_clone, (struct sock* newsk,  const struct request_sock* req), newsk, req);
LSM_STUB_FUNC_VOID(inet_conn_established, (struct sock* sk,  struct sk_buff* skb), sk, skb);
LSM_STUB_FUNC(secmark_relabel_packet, (u32 secid), secid);
LSM_STUB_FUNC_VOID(secmark_refcount_inc, (void));
LSM_STUB_FUNC_VOID(secmark_refcount_dec, (void));
LSM_STUB_FUNC_VOID(req_classify_flow, (const struct request_sock* req,  struct flowi* fl), req, fl);
LSM_STUB_FUNC(tun_dev_create, (void));
LSM_STUB_FUNC_VOID(tun_dev_post_create, (struct sock* sk), sk);
LSM_STUB_FUNC(tun_dev_attach, (struct sock* sk), sk);
#endif	/* CONFIG_SECURITY_NETWORK */
#ifdef CONFIG_SECURITY_NETWORK_XFRM
LSM_STUB_FUNC(xfrm_policy_alloc_security, (struct xfrm_sec_ctx** ctxp, struct xfrm_user_sec_ctx* sec_ctx), ctxp, sec_ctx);
LSM_STUB_FUNC(xfrm_policy_clone_security, (struct xfrm_sec_ctx* old_ctx,  struct xfrm_sec_ctx** new_ctx), old_ctx, new_ctx);
LSM_STUB_FUNC_VOID(xfrm_policy_free_security, (struct xfrm_sec_ctx* ctx), ctx);
LSM_STUB_FUNC(xfrm_policy_delete_security, (struct xfrm_sec_ctx* ctx), ctx);
LSM_STUB_FUNC(xfrm_state_alloc_security, (struct xfrm_state* x, struct xfrm_user_sec_ctx* sec_ctx, u32 secid), x, sec_ctx, secid);
LSM_STUB_FUNC_VOID(xfrm_state_free_security, (struct xfrm_state* x), x);
LSM_STUB_FUNC(xfrm_state_delete_security, (struct xfrm_state* x), x);
LSM_STUB_FUNC(xfrm_policy_lookup, (struct xfrm_sec_ctx* ctx,  u32 fl_secid,  u8 dir), ctx, fl_secid, dir);
LSM_STUB_FUNC(xfrm_state_pol_flow_match, (struct xfrm_state* x, struct xfrm_policy* xp, const struct flowi* fl), x, xp, fl);
LSM_STUB_FUNC(xfrm_decode_session, (struct sk_buff* skb,  u32* secid,  int ckall), skb, secid, ckall);
#endif	/* CONFIG_SECURITY_NETWORK_XFRM */
#ifdef CONFIG_KEYS
LSM_STUB_FUNC(key_alloc, (struct key* key,  const struct cred* cred,  unsigned long flags), key, cred, flags);
LSM_STUB_FUNC_VOID(key_free, (struct key* key), key);
LSM_STUB_FUNC(key_permission, (key_ref_t key_ref, const struct cred* cred, key_perm_t perm), key_ref, cred, perm);
LSM_STUB_FUNC(key_getsecurity, (struct key* key,  char** _buffer), key, _buffer);
#endif	/* CONFIG_KEYS */
#ifdef CONFIG_AUDIT
LSM_STUB_FUNC(audit_rule_init, (u32 field,  u32 op,  char* rulestr,  void** lsmrule), field, op, rulestr, lsmrule);
LSM_STUB_FUNC(audit_rule_known, (struct audit_krule* krule), krule);
LSM_STUB_FUNC(audit_rule_match, (u32 secid,  u32 field,  u32 op,  void* lsmrule, struct audit_context* actx), secid, field, op, lsmrule, actx);
LSM_STUB_FUNC_VOID(audit_rule_free, (void* lsmrule), lsmrule);
#endif /* CONFIG_AUDIT */

static struct security_operations lsmstub_wrapper_ops = {
  .name = "lsmstub",
  .ptrace_access_check = LSM_STUB_FUNC_NAME(ptrace_access_check),
  .ptrace_traceme = LSM_STUB_FUNC_NAME(ptrace_traceme),
  .capget = LSM_STUB_FUNC_NAME(capget),
  .capset = LSM_STUB_FUNC_NAME(capset),
  .capable = LSM_STUB_FUNC_NAME(capable),
  .quotactl = LSM_STUB_FUNC_NAME(quotactl),
  .quota_on = LSM_STUB_FUNC_NAME(quota_on),
  .syslog = LSM_STUB_FUNC_NAME(syslog),
  .settime = LSM_STUB_FUNC_NAME(settime),
  .vm_enough_memory = LSM_STUB_FUNC_NAME(vm_enough_memory),
  .bprm_set_creds = LSM_STUB_FUNC_NAME(bprm_set_creds),
  .bprm_check_security = LSM_STUB_FUNC_NAME(bprm_check_security),
  .bprm_secureexec = LSM_STUB_FUNC_NAME(bprm_secureexec),
  .bprm_committing_creds = LSM_STUB_FUNC_NAME(bprm_committing_creds),
  .bprm_committed_creds = LSM_STUB_FUNC_NAME(bprm_committed_creds),
  .sb_alloc_security = LSM_STUB_FUNC_NAME(sb_alloc_security),
  .sb_free_security = LSM_STUB_FUNC_NAME(sb_free_security),
  .sb_copy_data = LSM_STUB_FUNC_NAME(sb_copy_data),
  .sb_remount = LSM_STUB_FUNC_NAME(sb_remount),
  .sb_kern_mount = LSM_STUB_FUNC_NAME(sb_kern_mount),
  .sb_show_options = LSM_STUB_FUNC_NAME(sb_show_options),
  .sb_statfs = LSM_STUB_FUNC_NAME(sb_statfs),
  .sb_mount = LSM_STUB_FUNC_NAME(sb_mount),
  .sb_umount = LSM_STUB_FUNC_NAME(sb_umount),
  .sb_pivotroot = LSM_STUB_FUNC_NAME(sb_pivotroot),
  .sb_set_mnt_opts = LSM_STUB_FUNC_NAME(sb_set_mnt_opts),
  .sb_clone_mnt_opts = LSM_STUB_FUNC_NAME(sb_clone_mnt_opts),
  .sb_parse_opts_str = LSM_STUB_FUNC_NAME(sb_parse_opts_str),
#ifdef CONFIG_SECURITY_PATH
  .path_unlink = LSM_STUB_FUNC_NAME(path_unlink),
  .path_mkdir = LSM_STUB_FUNC_NAME(path_mkdir),
  .path_rmdir = LSM_STUB_FUNC_NAME(path_rmdir),
  .path_mknod = LSM_STUB_FUNC_NAME(path_mknod),
  .path_truncate = LSM_STUB_FUNC_NAME(path_truncate),
  .path_symlink = LSM_STUB_FUNC_NAME(path_symlink),
  .path_link = LSM_STUB_FUNC_NAME(path_link),
  .path_rename = LSM_STUB_FUNC_NAME(path_rename),
  .path_chmod = LSM_STUB_FUNC_NAME(path_chmod),
  .path_chown = LSM_STUB_FUNC_NAME(path_chown),
  .path_chroot = LSM_STUB_FUNC_NAME(path_chroot),
#endif
  .inode_alloc_security = LSM_STUB_FUNC_NAME(inode_alloc_security),
  .inode_free_security = LSM_STUB_FUNC_NAME(inode_free_security),
  .inode_init_security = LSM_STUB_FUNC_NAME(inode_init_security),
  .inode_create = LSM_STUB_FUNC_NAME(inode_create),
  .inode_link = LSM_STUB_FUNC_NAME(inode_link),
  .inode_unlink = LSM_STUB_FUNC_NAME(inode_unlink),
  .inode_symlink = LSM_STUB_FUNC_NAME(inode_symlink),
  .inode_mkdir = LSM_STUB_FUNC_NAME(inode_mkdir),
  .inode_rmdir = LSM_STUB_FUNC_NAME(inode_rmdir),
  .inode_mknod = LSM_STUB_FUNC_NAME(inode_mknod),
  .inode_rename = LSM_STUB_FUNC_NAME(inode_rename),
  .inode_readlink = LSM_STUB_FUNC_NAME(inode_readlink),
  .inode_follow_link = LSM_STUB_FUNC_NAME(inode_follow_link),
  .inode_permission = LSM_STUB_FUNC_NAME(inode_permission),
  .inode_setattr = LSM_STUB_FUNC_NAME(inode_setattr),
  .inode_getattr = LSM_STUB_FUNC_NAME(inode_getattr),
  .inode_setxattr = LSM_STUB_FUNC_NAME(inode_setxattr),
  .inode_post_setxattr = LSM_STUB_FUNC_NAME(inode_post_setxattr),
  .inode_getxattr = LSM_STUB_FUNC_NAME(inode_getxattr),
  .inode_listxattr = LSM_STUB_FUNC_NAME(inode_listxattr),
  .inode_removexattr = LSM_STUB_FUNC_NAME(inode_removexattr),
  .inode_need_killpriv = LSM_STUB_FUNC_NAME(inode_need_killpriv),
  .inode_killpriv = LSM_STUB_FUNC_NAME(inode_killpriv),
  .inode_getsecurity = LSM_STUB_FUNC_NAME(inode_getsecurity),
  .inode_setsecurity = LSM_STUB_FUNC_NAME(inode_setsecurity),
  .inode_listsecurity = LSM_STUB_FUNC_NAME(inode_listsecurity),
  .inode_getsecid = LSM_STUB_FUNC_NAME(inode_getsecid),
  .file_permission = LSM_STUB_FUNC_NAME(file_permission),
  .file_alloc_security = LSM_STUB_FUNC_NAME(file_alloc_security),
  .file_free_security = LSM_STUB_FUNC_NAME(file_free_security),
  .file_ioctl = LSM_STUB_FUNC_NAME(file_ioctl),
  .file_mmap = LSM_STUB_FUNC_NAME(file_mmap),
  .file_mprotect = LSM_STUB_FUNC_NAME(file_mprotect),
  .file_lock = LSM_STUB_FUNC_NAME(file_lock),
  .file_fcntl = LSM_STUB_FUNC_NAME(file_fcntl),
  .file_set_fowner = LSM_STUB_FUNC_NAME(file_set_fowner),
  .file_send_sigiotask = LSM_STUB_FUNC_NAME(file_send_sigiotask),
  .file_receive = LSM_STUB_FUNC_NAME(file_receive),
  .dentry_open = LSM_STUB_FUNC_NAME(dentry_open),
  .task_create = LSM_STUB_FUNC_NAME(task_create),
  .cred_alloc_blank = LSM_STUB_FUNC_NAME(cred_alloc_blank),
  .cred_free = LSM_STUB_FUNC_NAME(cred_free),
  .cred_transfer = LSM_STUB_FUNC_NAME(cred_transfer),
  .cred_prepare = LSM_STUB_FUNC_NAME(cred_prepare),
  .kernel_act_as = LSM_STUB_FUNC_NAME(kernel_act_as),
  .kernel_create_files_as = LSM_STUB_FUNC_NAME(kernel_create_files_as),
  .kernel_module_request = LSM_STUB_FUNC_NAME(kernel_module_request),
  .task_fix_setuid = LSM_STUB_FUNC_NAME(task_fix_setuid),
  .task_setpgid = LSM_STUB_FUNC_NAME(task_setpgid),
  .task_getpgid = LSM_STUB_FUNC_NAME(task_getpgid),
  .task_getsid = LSM_STUB_FUNC_NAME(task_getsid),
  .task_getsecid = LSM_STUB_FUNC_NAME(task_getsecid),
  .task_setnice = LSM_STUB_FUNC_NAME(task_setnice),
  .task_setioprio = LSM_STUB_FUNC_NAME(task_setioprio),
  .task_getioprio = LSM_STUB_FUNC_NAME(task_getioprio),
  .task_setrlimit = LSM_STUB_FUNC_NAME(task_setrlimit),
  .task_setscheduler = LSM_STUB_FUNC_NAME(task_setscheduler),
  .task_getscheduler = LSM_STUB_FUNC_NAME(task_getscheduler),
  .task_movememory = LSM_STUB_FUNC_NAME(task_movememory),
  .task_kill = LSM_STUB_FUNC_NAME(task_kill),
  .task_wait = LSM_STUB_FUNC_NAME(task_wait),
  .task_prctl = LSM_STUB_FUNC_NAME(task_prctl),
  .task_to_inode = LSM_STUB_FUNC_NAME(task_to_inode),
  .ipc_permission = LSM_STUB_FUNC_NAME(ipc_permission),
  .ipc_getsecid = LSM_STUB_FUNC_NAME(ipc_getsecid),
  .msg_msg_alloc_security = LSM_STUB_FUNC_NAME(msg_msg_alloc_security),
  .msg_msg_free_security = LSM_STUB_FUNC_NAME(msg_msg_free_security),
  .msg_queue_alloc_security = LSM_STUB_FUNC_NAME(msg_queue_alloc_security),
  .msg_queue_free_security = LSM_STUB_FUNC_NAME(msg_queue_free_security),
  .msg_queue_associate = LSM_STUB_FUNC_NAME(msg_queue_associate),
  .msg_queue_msgctl = LSM_STUB_FUNC_NAME(msg_queue_msgctl),
  .msg_queue_msgsnd = LSM_STUB_FUNC_NAME(msg_queue_msgsnd),
  .msg_queue_msgrcv = LSM_STUB_FUNC_NAME(msg_queue_msgrcv),
  .shm_alloc_security = LSM_STUB_FUNC_NAME(shm_alloc_security),
  .shm_free_security = LSM_STUB_FUNC_NAME(shm_free_security),
  .shm_associate = LSM_STUB_FUNC_NAME(shm_associate),
  .shm_shmctl = LSM_STUB_FUNC_NAME(shm_shmctl),
  .shm_shmat = LSM_STUB_FUNC_NAME(shm_shmat),
  .sem_alloc_security = LSM_STUB_FUNC_NAME(sem_alloc_security),
  .sem_free_security = LSM_STUB_FUNC_NAME(sem_free_security),
  .sem_associate = LSM_STUB_FUNC_NAME(sem_associate),
  .sem_semctl = LSM_STUB_FUNC_NAME(sem_semctl),
  .sem_semop = LSM_STUB_FUNC_NAME(sem_semop),
  .netlink_send = LSM_STUB_FUNC_NAME(netlink_send),
  .d_instantiate = LSM_STUB_FUNC_NAME(d_instantiate),
  .getprocattr = LSM_STUB_FUNC_NAME(getprocattr),
  .setprocattr = LSM_STUB_FUNC_NAME(setprocattr),
  .secid_to_secctx = LSM_STUB_FUNC_NAME(secid_to_secctx),
  .secctx_to_secid = LSM_STUB_FUNC_NAME(secctx_to_secid),
  .release_secctx = LSM_STUB_FUNC_NAME(release_secctx),
  .inode_notifysecctx = LSM_STUB_FUNC_NAME(inode_notifysecctx),
  .inode_setsecctx = LSM_STUB_FUNC_NAME(inode_setsecctx),
  .inode_getsecctx = LSM_STUB_FUNC_NAME(inode_getsecctx),
#ifdef CONFIG_SECURITY_NETWORK
  .unix_stream_connect = LSM_STUB_FUNC_NAME(unix_stream_connect),
  .unix_may_send = LSM_STUB_FUNC_NAME(unix_may_send),
  .socket_create = LSM_STUB_FUNC_NAME(socket_create),
  .socket_post_create = LSM_STUB_FUNC_NAME(socket_post_create),
  .socket_bind = LSM_STUB_FUNC_NAME(socket_bind),
  .socket_connect = LSM_STUB_FUNC_NAME(socket_connect),
  .socket_listen = LSM_STUB_FUNC_NAME(socket_listen),
  .socket_accept = LSM_STUB_FUNC_NAME(socket_accept),
  .socket_sendmsg = LSM_STUB_FUNC_NAME(socket_sendmsg),
  .socket_recvmsg = LSM_STUB_FUNC_NAME(socket_recvmsg),
  .socket_getsockname = LSM_STUB_FUNC_NAME(socket_getsockname),
  .socket_getpeername = LSM_STUB_FUNC_NAME(socket_getpeername),
  .socket_getsockopt = LSM_STUB_FUNC_NAME(socket_getsockopt),
  .socket_setsockopt = LSM_STUB_FUNC_NAME(socket_setsockopt),
  .socket_shutdown = LSM_STUB_FUNC_NAME(socket_shutdown),
  .socket_sock_rcv_skb = LSM_STUB_FUNC_NAME(socket_sock_rcv_skb),
  .socket_getpeersec_stream = LSM_STUB_FUNC_NAME(socket_getpeersec_stream),
  .socket_getpeersec_dgram = LSM_STUB_FUNC_NAME(socket_getpeersec_dgram),
  .sk_alloc_security = LSM_STUB_FUNC_NAME(sk_alloc_security),
  .sk_free_security = LSM_STUB_FUNC_NAME(sk_free_security),
  .sk_clone_security = LSM_STUB_FUNC_NAME(sk_clone_security),
  .sk_getsecid = LSM_STUB_FUNC_NAME(sk_getsecid),
  .sock_graft = LSM_STUB_FUNC_NAME(sock_graft),
  .inet_conn_request = LSM_STUB_FUNC_NAME(inet_conn_request),
  .inet_csk_clone = LSM_STUB_FUNC_NAME(inet_csk_clone),
  .inet_conn_established = LSM_STUB_FUNC_NAME(inet_conn_established),
  .secmark_relabel_packet = LSM_STUB_FUNC_NAME(secmark_relabel_packet),
  .secmark_refcount_inc = LSM_STUB_FUNC_NAME(secmark_refcount_inc),
  .secmark_refcount_dec = LSM_STUB_FUNC_NAME(secmark_refcount_dec),
  .req_classify_flow = LSM_STUB_FUNC_NAME(req_classify_flow),
  .tun_dev_create = LSM_STUB_FUNC_NAME(tun_dev_create),
  .tun_dev_post_create = LSM_STUB_FUNC_NAME(tun_dev_post_create),
  .tun_dev_attach = LSM_STUB_FUNC_NAME(tun_dev_attach),
#endif	/* CONFIG_SECURITY_NETWORK */
#ifdef CONFIG_SECURITY_NETWORK_XFRM
  .xfrm_policy_alloc_security = LSM_STUB_FUNC_NAME(xfrm_policy_alloc_security),
  .xfrm_policy_clone_security = LSM_STUB_FUNC_NAME(xfrm_policy_clone_security),
  .xfrm_policy_free_security = LSM_STUB_FUNC_NAME(xfrm_policy_free_security),
  .xfrm_policy_delete_security = LSM_STUB_FUNC_NAME(xfrm_policy_delete_security),
  .xfrm_state_alloc_security = LSM_STUB_FUNC_NAME(xfrm_state_alloc_security),
  .xfrm_state_free_security = LSM_STUB_FUNC_NAME(xfrm_state_free_security),
  .xfrm_state_delete_security = LSM_STUB_FUNC_NAME(xfrm_state_delete_security),
  .xfrm_policy_lookup = LSM_STUB_FUNC_NAME(xfrm_policy_lookup),
  .xfrm_state_pol_flow_match = LSM_STUB_FUNC_NAME(xfrm_state_pol_flow_match),
  .xfrm_decode_session = LSM_STUB_FUNC_NAME(xfrm_decode_session),
#endif	/* CONFIG_SECURITY_NETWORK_XFRM */
#ifdef CONFIG_KEYS
  .key_alloc = LSM_STUB_FUNC_NAME(key_alloc),
  .key_free = LSM_STUB_FUNC_NAME(key_free),
  .key_permission = LSM_STUB_FUNC_NAME(key_permission),
  .key_getsecurity = LSM_STUB_FUNC_NAME(key_getsecurity),
#endif	/* CONFIG_KEYS */
#ifdef CONFIG_AUDIT
  .audit_rule_init = LSM_STUB_FUNC_NAME(audit_rule_init),
  .audit_rule_known = LSM_STUB_FUNC_NAME(audit_rule_known),
  .audit_rule_match = LSM_STUB_FUNC_NAME(audit_rule_match),
  .audit_rule_free = LSM_STUB_FUNC_NAME(audit_rule_free),
#endif /* CONFIG_AUDIT */
};


static ssize_t active_lsm_read(struct file *filp, char __user *buf,
			       size_t count, loff_t *ppos)
{
  char name_buffer[SECURITY_NAME_MAX+2];
  char *mod_name = "none";
  unsigned int have_mod = 0;
  ssize_t rc;
  unsigned long lk_flags;

  if (*ppos != 0) 
    return 0;
  
  read_lock_irqsave(&lsmstub_ops_rwlock, lk_flags);
  if (lsmstub_mod_ops != NULL) {
    if (lsmstub_mod_ops->name != NULL) {
      mod_name = lsmstub_mod_ops->name;
      have_mod = 1;
    } else {
      mod_name = module_name(lsmstub_mod);
    }
  }
  snprintf(name_buffer, SECURITY_NAME_MAX+1, "%c%s\n", 
	   have_mod ? '+' : '-',
	   mod_name);
  read_unlock_irqrestore(&lsmstub_ops_rwlock, lk_flags);
  name_buffer[SECURITY_NAME_MAX+1] = 0x0;
  rc = simple_read_from_buffer(buf, count, ppos, name_buffer,
			       strlen(name_buffer));
  return rc;
}

static const struct file_operations active_lsm_fops = {
  .read = active_lsm_read,
};

int lsmstub_register(struct module* module,
		     struct security_operations *ops)
{
  unsigned long lk_flags;
  int error = 0;

  /* The first three checks can be done without acquiring
   * the write lock as they operate only on the information provided
   * to call to this function and not on lsmstub's state.
   */
  if (!lsmstub_registered) {
    printk(KERN_INFO "lsmstub: not registered as LSM.\n");
    error = 1;
    goto out;
  }

  if (ops == NULL || !within_module_core((unsigned long)ops, module)) {
    printk(KERN_INFO "lsmstub: ops address %p not inside module %s.\n",
	   ops, module_name(module));
    error = 2;
    goto out;
  }

  if (!within_module_core((unsigned long)ops->name, module)) {
    printk(KERN_INFO "lsmstub: ops->name address %p not inside module %s.\n",
	   ops, module_name(module));
    error = 3;
    goto out;
  }

  /* We need to acquire the write lock because we will not begin operating
   * on lsmstub's state.
   */
  write_lock_irqsave(&lsmstub_ops_rwlock, lk_flags);
  if (lsmstub_mod_ops != &lsmstub_null_ops) {
    printk(KERN_INFO "lsmstub: Ops already registered.\n");
    error = 4;
    goto out_unlock;
  }
  
  security_fixup_ops(ops);
  lsmstub_mod_ops = ops;
  lsmstub_mod = module;
  lsmstub_mod_registered = 1;

  printk(KERN_INFO "lsmstub: registered module %s with ops at %p\n",
	 module_name(lsmstub_mod), lsmstub_mod_ops);
 out_unlock:
  write_unlock_irqrestore(&lsmstub_ops_rwlock, lk_flags);
 out:
  return error;
}
EXPORT_SYMBOL_GPL(lsmstub_register);

int lsmstub_unregister(struct security_operations *ops)
{
  unsigned long lk_flags;
  int error = 0;
  if (!lsmstub_registered) {
    printk(KERN_INFO "lsmstub: not registered as LSM.\n");
    error = 1;
    goto out;
  }

  write_lock_irqsave(&lsmstub_ops_rwlock, lk_flags);
  if (lsmstub_mod_ops != ops) {
    printk(KERN_INFO "lsmstub: Ops not registered.\n");
    error = 2;
    goto out_unlock;
  }

  lsmstub_mod_registered = 0;
  printk(KERN_INFO "lsmstub: unregistered module %s with ops at %p.\n",
	 module_name(lsmstub_mod), lsmstub_mod_ops);
  lsmstub_mod_ops = &lsmstub_null_ops;
  lsmstub_mod = NULL;
		     
 out_unlock:
  write_unlock_irqrestore(&lsmstub_ops_rwlock, lk_flags);
 out:
  return error;
}
EXPORT_SYMBOL_GPL(lsmstub_unregister);

static int __init lsmstub_fsinit(void)
{
  int error = 0;
  if (!lsmstub_registered)
    return 0;

  if (lsmstub_fs_dentry != NULL) {
    printk(KERN_INFO "lsmstub: securityfs exists.\n");
    return -EEXIST;
  }

  /* Now initialize securityfs... */
  lsmstub_fs_dentry = securityfs_create_dir("lsmstub", NULL);
  if (IS_ERR(lsmstub_fs_dentry)) {
    error = PTR_ERR(lsmstub_fs_dentry);
    printk(KERN_INFO "lsmstub: unable to create securityfs directory.\n");
    lsmstub_fs_dentry = NULL;
    goto out;
  }

  lsmstub_lsm_dentry = securityfs_create_file("active_lsm",
					       S_IFREG | 0640,
					       lsmstub_fs_dentry,
					       NULL,
					       &active_lsm_fops);
  if (IS_ERR(lsmstub_lsm_dentry)) {
    error = PTR_ERR(lsmstub_lsm_dentry);
    securityfs_remove(lsmstub_fs_dentry);
    printk(KERN_INFO "lsmstub: unable to create active_lsm file.\n");
    lsmstub_fs_dentry = NULL;
    lsmstub_lsm_dentry = NULL;
    goto out;
  }
  printk(KERN_INFO "lsmstub: security initialized.\n");
 out:
  return error;
}

static int __init lsmstub_init(void)
{
  int error = 0;

  if (!security_module_enable(&lsmstub_wrapper_ops)) {
    printk(KERN_INFO "lsmstub: disabled by boot time parameter.\n");
    goto out;
  }

  lsmstub_mod = NULL;
  lsmstub_mod_registered = 0;
  
  error = register_security(&lsmstub_wrapper_ops);
  if (error) {
    printk(KERN_INFO "lsmstub: unable to register lsmstub.\n");
    securityfs_remove(lsmstub_lsm_dentry);
    securityfs_remove(lsmstub_fs_dentry);
    lsmstub_fs_dentry = NULL;
    lsmstub_lsm_dentry = NULL;
    goto out;
  }
  
  lsmstub_registered = 1;
  security_fixup_ops(&lsmstub_null_ops);
  lsmstub_mod_ops = &lsmstub_null_ops;
  printk(KERN_INFO "lsmstub: initialized.\n");
 out:
  return error;
}

security_initcall(lsmstub_init);
fs_initcall(lsmstub_fsinit);
