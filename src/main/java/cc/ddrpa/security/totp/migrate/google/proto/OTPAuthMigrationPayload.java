// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: payload.proto

package cc.ddrpa.security.totp.migrate.google.proto;

public final class OTPAuthMigrationPayload {
  private OTPAuthMigrationPayload() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_cc_ddrpa_security_totp_migrate_google_proto_Payload_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_cc_ddrpa_security_totp_migrate_google_proto_Payload_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_cc_ddrpa_security_totp_migrate_google_proto_Payload_OtpParameters_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_cc_ddrpa_security_totp_migrate_google_proto_Payload_OtpParameters_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n\rpayload.proto\022+cc.ddrpa.security.totp." +
      "migrate.google.proto\"\217\006\n\007Payload\022Z\n\016otp_" +
      "parameters\030\001 \003(\0132B.cc.ddrpa.security.tot" +
      "p.migrate.google.proto.Payload.OtpParame" +
      "ters\022\017\n\007version\030\002 \001(\005\022\022\n\nbatch_size\030\003 \001(" +
      "\005\022\023\n\013batch_index\030\004 \001(\005\022\020\n\010batch_id\030\005 \001(\005" +
      "\032\276\002\n\rOtpParameters\022\016\n\006secret\030\001 \001(\014\022\014\n\004na" +
      "me\030\002 \001(\t\022\016\n\006issuer\030\003 \001(\t\022Q\n\talgorithm\030\004 " +
      "\001(\0162>.cc.ddrpa.security.totp.migrate.goo" +
      "gle.proto.Payload.Algorithm\022O\n\006digits\030\005 " +
      "\001(\0162?.cc.ddrpa.security.totp.migrate.goo" +
      "gle.proto.Payload.DigitCount\022J\n\004type\030\006 \001" +
      "(\0162<.cc.ddrpa.security.totp.migrate.goog" +
      "le.proto.Payload.OtpType\022\017\n\007counter\030\007 \001(" +
      "\003\"y\n\tAlgorithm\022\031\n\025ALGORITHM_UNSPECIFIED\020" +
      "\000\022\022\n\016ALGORITHM_SHA1\020\001\022\024\n\020ALGORITHM_SHA25" +
      "6\020\002\022\024\n\020ALGORITHM_SHA512\020\003\022\021\n\rALGORITHM_M" +
      "D5\020\004\"U\n\nDigitCount\022\033\n\027DIGIT_COUNT_UNSPEC" +
      "IFIED\020\000\022\023\n\017DIGIT_COUNT_SIX\020\001\022\025\n\021DIGIT_CO" +
      "UNT_EIGHT\020\002\"I\n\007OtpType\022\030\n\024OTP_TYPE_UNSPE" +
      "CIFIED\020\000\022\021\n\rOTP_TYPE_HOTP\020\001\022\021\n\rOTP_TYPE_" +
      "TOTP\020\002BH\n+cc.ddrpa.security.totp.migrate" +
      ".google.protoB\027OTPAuthMigrationPayloadP\001"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
        });
    internal_static_cc_ddrpa_security_totp_migrate_google_proto_Payload_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_cc_ddrpa_security_totp_migrate_google_proto_Payload_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_cc_ddrpa_security_totp_migrate_google_proto_Payload_descriptor,
        new java.lang.String[] { "OtpParameters", "Version", "BatchSize", "BatchIndex", "BatchId", });
    internal_static_cc_ddrpa_security_totp_migrate_google_proto_Payload_OtpParameters_descriptor =
      internal_static_cc_ddrpa_security_totp_migrate_google_proto_Payload_descriptor.getNestedTypes().get(0);
    internal_static_cc_ddrpa_security_totp_migrate_google_proto_Payload_OtpParameters_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_cc_ddrpa_security_totp_migrate_google_proto_Payload_OtpParameters_descriptor,
        new java.lang.String[] { "Secret", "Name", "Issuer", "Algorithm", "Digits", "Type", "Counter", });
  }

  // @@protoc_insertion_point(outer_class_scope)
}
