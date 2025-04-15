
#ifndef KM_H
#define KM_H


#define USE_SDF
/* #undef USE_PIICO */
/* #undef USE_GMSSL */

#ifdef USE_SDF

#include <sdf/libsdf.h>
#include <sdfkmt/sdfe-func.h>
#include <sdfkmt/sdfe-type.h>
#endif

#ifdef USE_PIICO
#include <piico_pc/api.h>
#include <piico_pc/piico_define.h>
#include <piico_pc/piico_error.h>
#endif

#endif
