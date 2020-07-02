#import "CipherMessage.h"

NS_ASSUME_NONNULL_BEGIN

@interface ClosedGroupCiphertextMessage : NSObject<CipherMessage>

@property (nonatomic, readonly) NSData *serialized;
@property (nonatomic, readonly) NSData *ivAndCiphertext;
@property (nonatomic, readonly) NSString *senderPublicKey;
@property (nonatomic, readonly) uint32_t keyIndex;

- (instancetype)init_throws_withIVAndCiphertext:(NSData *)ivAndCiphertext senderPublicKey:(NSString *)senderPublicKey keyIndex:(uint32_t)keyIndex;
- (instancetype)init_throws_withData:(NSData *)serialized;

@end

NS_ASSUME_NONNULL_END

