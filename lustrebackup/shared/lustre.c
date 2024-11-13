/* --- BEGIN_HEADER ---

lustre - shared library functions for Python lustre backup
Copyright (C) 2020-2024  The lustrebackup Project by the Science HPC Center at UCPH

This file is part of lustrebackup.

Python lustre backup is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

Python lustre backup is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

-- END_HEADER --- */

/* Inspired by lustre/utils/lustre_rsync.c */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <stdarg.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <limits.h>
#include <utime.h>
#include <time.h>
#include <sys/xattr.h>
#include <linux/types.h>
#include <syslog.h>

/* Lustre includes are relative to lustre-release:
 * VERSION=2.12.4
 * git clone git://git.whamcloud.com/fs/lustre-release.git
 * cd lustre-release
 * git checkout ${VERSION}
*/
   
#include <libcfs/util/string.h>
#include <lustre/lustreapi.h>
#include <uapi/linux/lustre/lustre_user.h>
#include <Python.h>


#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#if (_DEBUG == 1)
#define WRITELOGMESSAGE(priority, format, ...) \
    fprintf(stderr, #priority ": " __FILE__"("TOSTRING(__LINE__)"): " format, ##__VA_ARGS__)
#else
#define WRITELOGMESSAGE(priority, format, ...) \
    if (priority != LOG_DEBUG) fprintf(stderr, #priority ": " format, ##__VA_ARGS__)
#endif 

/* Define lustre constants */

#define LR_FID_STR_LEN 128


static PyObject* lfs_debug(PyObject* self, PyObject *args) {
        /* Returns tuple with:
    rc:         Return code
    path:       path
    */

    /* Parse python arguments int C variables */

    char        *lr_path              = NULL;

    // https://docs.python.org/3/c-api/arg.html
    if(!PyArg_ParseTuple(args, 
                        "s",
                        &lr_path
                        )) {
        return NULL;
    }
    
    WRITELOGMESSAGE(LOG_DEBUG, "=================================================================\n");
    WRITELOGMESSAGE(LOG_DEBUG, "lfs_debug.lr_path: %s\n", lr_path);
    WRITELOGMESSAGE(LOG_DEBUG, "=================================================================\n");


    /* End: Parse python arguments int C variables */

    int         rc                      = 0;    
    int         fd;
    PyObject    *result                 = NULL;

    fd = open(lr_path, O_RDONLY);
    if (fd < 0) {
        rc = -errno;
        WRITELOGMESSAGE(LOG_ERR, "data_version: cannot open file: '%s: %s\n", lr_path, strerror(-rc));
    }
    else {
        close(fd);
    }
    // https://docs.python.org/3/c-api/arg.html
    result = Py_BuildValue("i", \
                            rc);

    return result;
}


static PyObject* lfs_data_version(PyObject* self, PyObject *args) {
    /* Returns tuple with:
    rc:         Return code
    path:       path
    */

    /* Parse python arguments int C variables */

    char        *lr_path              = NULL;
    int         lr_flush_dirty        = 0;

    // https://docs.python.org/3/c-api/arg.html
    if(!PyArg_ParseTuple(args, 
                        "si",
                        &lr_path,
                        &lr_flush_dirty
                        )) {
        return NULL;
    }
    
    WRITELOGMESSAGE(LOG_DEBUG, "=================================================================\n");
    WRITELOGMESSAGE(LOG_DEBUG, "lfs_data_version.lr_path: %s\n", lr_path);
    WRITELOGMESSAGE(LOG_DEBUG, "lfs_data_version.lr_flush_dirty: %d\n", lr_flush_dirty);
    WRITELOGMESSAGE(LOG_DEBUG, "=================================================================\n");


    /* End: Parse python arguments int C variables */

    int         rc                      = 0;    
    int         fd;
    int         data_version_flags      = 0;
    __u64       data_version;
    PyObject    *result                 = NULL;

    if (lr_flush_dirty == 1) {
        data_version_flags = LL_DV_RD_FLUSH;
    }
    
    fd = open(lr_path, O_RDONLY);
    if (fd < 0) {
        rc = -errno;
        WRITELOGMESSAGE(LOG_ERR, "data_version: cannot open file: '%s: %s\n", lr_path, strerror(-rc));
    }
    else {
        rc = llapi_get_data_version(fd, &data_version, data_version_flags);
        if (rc != 0) {
            WRITELOGMESSAGE(LOG_ERR, "data_version: cannot get version for '%s': %s\n",
                lr_path, strerror(-rc));
        }
        close(fd);
    }
    if (rc != 0) data_version = 0;

     WRITELOGMESSAGE(LOG_DEBUG, "rc: %d, data_version_flags: %d, path: %s, data_version: %llu\n", 
        rc, data_version_flags, lr_path, data_version);

    // https://docs.python.org/3/c-api/arg.html
    result = Py_BuildValue("(i,K)", \
                            rc,
                            data_version);

    return result;
}


static PyObject* lfs_fid2path(PyObject* self, PyObject *args) {
    /* Returns tuple with:
    rc:         Return code
    path:       path
    */

    /* Parse python arguments int C variables */

	char        *lr_mount              = NULL;
	char        *lr_fidstr             = NULL;
    
    // https://docs.python.org/3/c-api/arg.html
    if(!PyArg_ParseTuple(args, 
                        "ss",
                        &lr_mount,
                        &lr_fidstr
                        )) {
        return NULL;
    }
    
    WRITELOGMESSAGE(LOG_DEBUG, "=================================================================\n");
    WRITELOGMESSAGE(LOG_DEBUG, "lfs_fid2path.lr_mount: %s\n", lr_mount);
    WRITELOGMESSAGE(LOG_DEBUG, "lfs_fid2path.lr_fidstr: %s\n", lr_fidstr);
    WRITELOGMESSAGE(LOG_DEBUG, "=================================================================\n");

    /* End: Parse python arguments int C variables */

    int         rc                      = 0;
    char        path[PATH_MAX];
    int 		linkno                  = 0;
    long long 	recno                   = -1;
    PyObject    *result                 = NULL;

	rc = llapi_fid2path(lr_mount, lr_fidstr, &path[0],
			   PATH_MAX, &recno, &linkno);
    // If path was not resolved then set path to empty string
    if (rc != 0) {
        path[0] = '\0';
    }

    if (rc < 0 && rc != -ENOENT) {
        WRITELOGMESSAGE(LOG_ERR, "lfs_fid2path error: (%s, %s) %d %s\n",
            lr_mount, lr_fidstr, -rc, strerror(errno = -rc));
    }
    WRITELOGMESSAGE(LOG_DEBUG, "rc: %d, path: %s, recno: %lld, linkno: %d\n", rc, &path[0], recno, linkno);

    // https://docs.python.org/3/c-api/arg.html
    result = Py_BuildValue("(i,s)", \
                            rc,
                            &path[0]);

    return result;
}


static PyObject* lfs_path2fid(PyObject* self, PyObject *args) {
    /* Returns tuple with:
    rc:         Return code
    fid:        fid
    */

    /* Parse python arguments int C variables */

    char        *lr_path               = NULL;
    
    // https://docs.python.org/3/c-api/arg.html
    if(!PyArg_ParseTuple(args, 
                        "s",
                        &lr_path
                        )) {
        return NULL;
    }
    
    WRITELOGMESSAGE(LOG_DEBUG, "=================================================================\n");
    WRITELOGMESSAGE(LOG_DEBUG, "lfs_path2fid.lr_path: %s\n", lr_path);
    WRITELOGMESSAGE(LOG_DEBUG, "=================================================================\n");

    /* End: Parse python arguments int C variables */

    int         rc                      = 0;
    char        fid_str[LR_FID_STR_LEN];
    struct      lu_fid fid;
    PyObject    *result                 = NULL;

    rc = llapi_path2fid(lr_path, &fid);

    // If path was not resolved then set fid_str to empty string
    if (rc != 0) {
        fid_str[0] = '\0';
    }

    if (rc < 0 && rc != -ENOENT) {
        WRITELOGMESSAGE(LOG_ERR, "lfs_path2fid error: (%s) %d %s\n",
            lr_path, -rc, strerror(errno = -rc));
    }
    sprintf(&fid_str[0], "[%#llx:0x%x:0x%x]", PFID(&fid));
    WRITELOGMESSAGE(LOG_DEBUG, "rc: %d, path: %s, fid_str: %s\n", 
        rc, &lr_path[0], fid_str);

    // https://docs.python.org/3/c-api/arg.html
    result = Py_BuildValue("(i,s)", \
                            rc,
                            &fid_str[0]);

    return result;
}


/* Python3 extension (glue) code 
 * https://docs.python.org/3.6/howto/cporting.html
*/

struct module_state {
    PyObject *error;
};

#define GETSTATE(m) ((struct module_state*)PyModule_GetState(m))

static char lustre_docs[] = \
    "Python lustre backup extensions.\n";


static PyMethodDef lustre_funcs[] = {
    {"lfs_path2fid", (PyCFunction) lfs_path2fid, METH_VARARGS, "Get lustre fid from path\n"},
    {"lfs_fid2path", (PyCFunction) lfs_fid2path, METH_VARARGS, "Get lustre path from fid\n"},
    {"lfs_data_version", (PyCFunction) lfs_data_version, METH_VARARGS, "Get lustre data_version from path\n"},
    {"lfs_debug", (PyCFunction) lfs_debug, METH_VARARGS, "Lustre debug\n"},
    {NULL}
};

static int lustre_traverse(PyObject *m, visitproc visit, void *arg) {
    Py_VISIT(GETSTATE(m)->error);
    return 0;
}

static int lustre_clear(PyObject *m) {
    Py_CLEAR(GETSTATE(m)->error);
    return 0;
}


static struct PyModuleDef moduledef = {
        PyModuleDef_HEAD_INIT,
        "lustre",
        lustre_docs,
        sizeof(struct module_state),
        lustre_funcs,
        NULL,
        lustre_traverse,
        lustre_clear,
        NULL
};


#define INITERROR return NULL

PyMODINIT_FUNC PyInit_lustre(void) {
    PyObject *module = PyModule_Create(&moduledef);

    if (module == NULL)
        INITERROR;
    struct module_state *st = GETSTATE(module);

    st->error = PyErr_NewException("lustre.Error", NULL, NULL);
    if (st->error == NULL) {
        Py_DECREF(module);
        INITERROR;
    }

    return module;
}