#ifdef __OBJC__
#import <UIKit/UIKit.h>
#else
#ifndef FOUNDATION_EXPORT
#if defined(__cplusplus)
#define FOUNDATION_EXPORT extern "C"
#else
#define FOUNDATION_EXPORT extern
#endif
#endif
#endif

#import "Curve25519.h"
#import "Ed25519.h"
#import "SessionCurve25519Kit.h"

FOUNDATION_EXPORT double SessionCurve25519KitVersionNumber;
FOUNDATION_EXPORT const unsigned char SessionCurve25519KitVersionString[];

