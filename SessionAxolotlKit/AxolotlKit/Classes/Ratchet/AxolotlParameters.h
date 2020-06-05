//
//  Copyright (c) 2017 Open Whisper Systems. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <SessionCurve25519Kit/Curve25519.h>

@protocol AxolotlParameters <NSObject>

@property (nonatomic) ECKeyPair *ourIdentityKeyPair;
@property (nonatomic) NSData    *theirIdentityKey;

@end
