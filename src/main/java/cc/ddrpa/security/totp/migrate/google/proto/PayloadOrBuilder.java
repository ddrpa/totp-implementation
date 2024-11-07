// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: payload.proto

package cc.ddrpa.security.totp.migrate.google.proto;

public interface PayloadOrBuilder extends
    // @@protoc_insertion_point(interface_extends:cc.ddrpa.security.totp.migrate.google.proto.Payload)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>repeated .cc.ddrpa.security.totp.migrate.google.proto.Payload.OtpParameters otp_parameters = 1;</code>
   */
  java.util.List<cc.ddrpa.security.totp.migrate.google.proto.Payload.OtpParameters> 
      getOtpParametersList();
  /**
   * <code>repeated .cc.ddrpa.security.totp.migrate.google.proto.Payload.OtpParameters otp_parameters = 1;</code>
   */
  cc.ddrpa.security.totp.migrate.google.proto.Payload.OtpParameters getOtpParameters(int index);
  /**
   * <code>repeated .cc.ddrpa.security.totp.migrate.google.proto.Payload.OtpParameters otp_parameters = 1;</code>
   */
  int getOtpParametersCount();
  /**
   * <code>repeated .cc.ddrpa.security.totp.migrate.google.proto.Payload.OtpParameters otp_parameters = 1;</code>
   */
  java.util.List<? extends cc.ddrpa.security.totp.migrate.google.proto.Payload.OtpParametersOrBuilder> 
      getOtpParametersOrBuilderList();
  /**
   * <code>repeated .cc.ddrpa.security.totp.migrate.google.proto.Payload.OtpParameters otp_parameters = 1;</code>
   */
  cc.ddrpa.security.totp.migrate.google.proto.Payload.OtpParametersOrBuilder getOtpParametersOrBuilder(
      int index);

  /**
   * <code>optional int32 version = 2;</code>
   * @return Whether the version field is set.
   */
  boolean hasVersion();
  /**
   * <code>optional int32 version = 2;</code>
   * @return The version.
   */
  int getVersion();

  /**
   * <code>optional int32 batch_size = 3;</code>
   * @return Whether the batchSize field is set.
   */
  boolean hasBatchSize();
  /**
   * <code>optional int32 batch_size = 3;</code>
   * @return The batchSize.
   */
  int getBatchSize();

  /**
   * <code>optional int32 batch_index = 4;</code>
   * @return Whether the batchIndex field is set.
   */
  boolean hasBatchIndex();
  /**
   * <code>optional int32 batch_index = 4;</code>
   * @return The batchIndex.
   */
  int getBatchIndex();

  /**
   * <code>optional int32 batch_id = 5;</code>
   * @return Whether the batchId field is set.
   */
  boolean hasBatchId();
  /**
   * <code>optional int32 batch_id = 5;</code>
   * @return The batchId.
   */
  int getBatchId();
}