#ifndef _EFI_MP_
#include <efi.h>
#include <lib.h>
#include <efilib.h>
#endif

#define EFI_MP_SERVICES_PROTOCOL_GUID \
  { 0x3fdda605, 0xa76e, 0x4f46, {0xad, 0x29, 0x12, 0xf4, 0x53, 0x1b, 0x3d, 0x08} }

typedef struct _EFI_MP_SERVICES_PROTOCOL EFI_MP_SERVICES_PROTOCOL;

#define PROCESSOR_AS_BSP_BIT         0x00000001
#define PROCESSOR_ENABLED_BIT        0x00000002
#define PROCESSOR_HEALTH_STATUS_BIT  0x00000004

typedef struct {
  UINT64                     ProcessorId;
  UINT32                     StatusFlag;
} EFI_PROCESSOR_INFORMATION;

typedef
EFI_STATUS
(EFIAPI *EFI_MP_SERVICES_DUMMY)(
  IN  EFI_MP_SERVICES_PROTOCOL  *This
  );

typedef
VOID
(EFIAPI *EFI_AP_PROCEDURE)(
  IN OUT VOID *Buffer
  );

typedef
EFI_STATUS
(EFIAPI *EFI_MP_SERVICES_GET_NUMBER_OF_PROCESSORS)(
  IN  EFI_MP_SERVICES_PROTOCOL  *This,
  OUT UINTN                     *NumberOfProcessors,
  OUT UINTN                     *NumberOfEnabledProcessors
  );

typedef
EFI_STATUS
(EFIAPI *EFI_MP_SERVICES_GET_PROCESSOR_INFO)(
  IN  EFI_MP_SERVICES_PROTOCOL   *This,
  IN  UINTN                      ProcessorNumber,
  OUT EFI_PROCESSOR_INFORMATION  *ProcessorInfoBuffer
  );

typedef
EFI_STATUS
(EFIAPI *EFI_MP_SERVICES_STARTUP_ALL_APS) (
  IN EFI_MP_SERVICES_PROTOCOL *This,
  IN EFI_AP_PROCEDURE Procedure,
  IN BOOLEAN SingleThread,
  IN EFI_EVENT WaitEvent OPTIONAL,
  IN UINTN TimeoutInMicroSeconds,
  IN VOID *ProcedureArgument OPTIONAL,
  OUT UINTN **FailedCpuList OPTIONAL
  );

typedef
EFI_STATUS
(EFIAPI *EFI_MP_SERVICES_STARTUP_THIS_AP)(
  IN  EFI_MP_SERVICES_PROTOCOL  *This,
  IN  EFI_AP_PROCEDURE          Procedure,
  IN  UINTN                     ProcessorNumber,
  IN  EFI_EVENT                 WaitEvent               OPTIONAL,
  IN  UINTN                     TimeoutInMicroseconds,
  IN  VOID                      *ProcedureArgument      OPTIONAL,
  OUT BOOLEAN                   *Finished               OPTIONAL
  );

typedef
EFI_STATUS
(EFIAPI *EFI_MP_SERVICES_WHOAMI) (
  IN EFI_MP_SERVICES_PROTOCOL *This,
  OUT UINTN                   *ProcessorNumber
  );

struct _EFI_MP_SERVICES_PROTOCOL {
  EFI_MP_SERVICES_GET_NUMBER_OF_PROCESSORS  GetNumberOfProcessors;
  EFI_MP_SERVICES_GET_PROCESSOR_INFO        GetProcessorInfo;
  EFI_MP_SERVICES_STARTUP_ALL_APS           StartupAllAPs;
  EFI_MP_SERVICES_STARTUP_THIS_AP           StartupThisAP;
  EFI_MP_SERVICES_DUMMY                     SwitchBSP;
  EFI_MP_SERVICES_DUMMY                     EnableDisableAP;
  EFI_MP_SERVICES_WHOAMI                    WhoAmI;
};