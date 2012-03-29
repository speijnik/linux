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

#ifndef _LINUX_LSMSTUB_H
#define _LINUX_LSMSTUB_H

struct module;
struct security_operations;

extern int lsmstub_register(struct module* module,
			    struct security_operations *ops);
extern int lsmstub_unregister(struct security_operations *ops);

#endif /* _LINUX_LSMSTUB_H */
