#import "LokiFriendRequestMessage.h"

@implementation LokiFriendRequestMessage

- (instancetype)init_throws_withData:(NSData *)serialized
{
    if (self = [super init]) {
        _serialized = serialized;
    }
    return self;
}

- (CipherMessageType)cipherMessageType
{
    return CipherMessageType_LokiFriendRequest;
}

@end
