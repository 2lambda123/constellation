//go:build enterprise

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: AGPL-3.0-only
*/

package measurements

import "github.com/edgelesssys/constellation/v2/internal/cloud/cloudprovider"

// Regenerate the measurements by running go generate.
// The enterprise build tag is required to validate the measurements using production
// sigstore certificates.
//go:generate go run -tags enterprise measurement-generator/generate.go

// DefaultsFor provides the default measurements for given cloud provider.
func DefaultsFor(provider cloudprovider.Provider) M {
	switch provider {
	case cloudprovider.AWS:
		return M{
			0: {
				Expected: [32]byte{
					0x73, 0x7f, 0x76, 0x7a, 0x12, 0xf5, 0x4e, 0x70,
					0xee, 0xcb, 0xc8, 0x68, 0x40, 0x11, 0x32, 0x3a,
					0xe2, 0xfe, 0x2d, 0xd9, 0xf9, 0x07, 0x85, 0x57,
					0x79, 0x69, 0xd7, 0xa2, 0x01, 0x3e, 0x8c, 0x12,
				},
				WarnOnly: true,
			},
			2: {
				Expected: [32]byte{
					0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea,
					0x1f, 0x44, 0x3f, 0x15, 0x62, 0xbe, 0xec, 0x8d,
					0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f, 0xcf, 0x9a,
					0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69,
				},
				WarnOnly: true,
			},
			3: {
				Expected: [32]byte{
					0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea,
					0x1f, 0x44, 0x3f, 0x15, 0x62, 0xbe, 0xec, 0x8d,
					0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f, 0xcf, 0x9a,
					0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69,
				},
				WarnOnly: true,
			},
			4: {
				Expected: [32]byte{
					0x9e, 0xf9, 0xa6, 0x6f, 0x2f, 0x5f, 0x85, 0xa6,
					0xd6, 0x64, 0x9e, 0x19, 0x4c, 0xa0, 0x40, 0xe9,
					0x5f, 0xae, 0x67, 0x4b, 0x29, 0xad, 0xbb, 0xea,
					0x12, 0xa1, 0xd1, 0x59, 0x5c, 0xa9, 0xa6, 0x18,
				},
				WarnOnly: false,
			},
			6: {
				Expected: [32]byte{
					0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea,
					0x1f, 0x44, 0x3f, 0x15, 0x62, 0xbe, 0xec, 0x8d,
					0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f, 0xcf, 0x9a,
					0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69,
				},
				WarnOnly: true,
			},
			7: {
				Expected: [32]byte{
					0x12, 0x0e, 0x49, 0x8d, 0xb2, 0xa2, 0x24, 0xbd,
					0x51, 0x2b, 0x6e, 0xfc, 0x9b, 0x02, 0x34, 0xf8,
					0x43, 0xe1, 0x0b, 0xf0, 0x61, 0xeb, 0x7a, 0x76,
					0xec, 0xca, 0x55, 0x09, 0xa2, 0x23, 0x89, 0x01,
				},
				WarnOnly: true,
			},
			8: {
				Expected: [32]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				WarnOnly: false,
			},
			9: {
				Expected: [32]byte{
					0x04, 0xb6, 0x7d, 0x41, 0xde, 0x6e, 0xe2, 0xd6,
					0xdc, 0x90, 0x37, 0xb2, 0x7a, 0xca, 0x64, 0x2d,
					0x9a, 0x97, 0xa3, 0xfe, 0x93, 0xee, 0xe1, 0x71,
					0xfe, 0x88, 0xfc, 0x88, 0x32, 0x18, 0x92, 0xc7,
				},
				WarnOnly: false,
			},
			11: {Expected: [32]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
				WarnOnly: false,
			}, 12: {Expected: [32]byte{
				0x06, 0xa2, 0x06, 0x5c, 0x57, 0x73, 0xe7, 0x1c,
				0xce, 0x23, 0xe1, 0x78, 0x76, 0xd0, 0x8a, 0x75,
				0x53, 0x50, 0x3f, 0x6a, 0x4d, 0xd5, 0xbd, 0x3a,
				0x34, 0x8b, 0x31, 0x44, 0x88, 0x7e, 0x80, 0xf4,
			},
				WarnOnly: false,
			}, 13: {Expected: [32]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
				WarnOnly: false,
			}, 14: {Expected: [32]byte{
				0xd7, 0xc4, 0xcc, 0x7f, 0xf7, 0x93, 0x30, 0x22,
				0xf0, 0x13, 0xe0, 0x3b, 0xde, 0xe8, 0x75, 0xb9,
				0x17, 0x20, 0xb5, 0xb8, 0x6c, 0xf1, 0x75, 0x3c,
				0xad, 0x83, 0x0f, 0x95, 0xe7, 0x91, 0x92, 0x6f,
			},
				WarnOnly: true,
			},
			15: {
				Expected: [32]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				WarnOnly: false,
			}}

	case cloudprovider.Azure:
		return M{
			1: {
				Expected: [32]byte{
					0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea,
					0x1f, 0x44, 0x3f, 0x15, 0x62, 0xbe, 0xec, 0x8d,
					0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f, 0xcf, 0x9a,
					0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69,
				},
				WarnOnly: true,
			},
			2: {
				Expected: [32]byte{
					0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea,
					0x1f, 0x44, 0x3f, 0x15, 0x62, 0xbe, 0xec, 0x8d,
					0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f, 0xcf, 0x9a,
					0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69,
				},
				WarnOnly: true,
			},
			3: {
				Expected: [32]byte{
					0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea,
					0x1f, 0x44, 0x3f, 0x15, 0x62, 0xbe, 0xec, 0x8d,
					0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f, 0xcf, 0x9a,
					0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69,
				},
				WarnOnly: true,
			},
			4: {
				Expected: [32]byte{
					0xff, 0x9d, 0x44, 0x8b, 0xeb, 0x69, 0xc3, 0xea,
					0x8c, 0xda, 0x6b, 0x2e, 0xce, 0xb6, 0x1d, 0x70,
					0x10, 0xb3, 0xca, 0x92, 0xd3, 0xaa, 0xea, 0x35,
					0x0e, 0x48, 0x8b, 0x15, 0x03, 0x12, 0x66, 0xcf,
				},
				WarnOnly: false,
			},
			7: {
				Expected: [32]byte{
					0x34, 0x65, 0x47, 0xa8, 0xce, 0x59, 0x57, 0xaf,
					0x27, 0xe5, 0x52, 0x42, 0x7d, 0x6b, 0x9e, 0x6d,
					0x9c, 0xb5, 0x02, 0xf0, 0x15, 0x6e, 0x91, 0x55,
					0x38, 0x04, 0x51, 0xee, 0xa1, 0xb3, 0xf0, 0xed,
				},
				WarnOnly: true,
			},
			8: {
				Expected: [32]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				WarnOnly: false,
			},
			9: {
				Expected: [32]byte{
					0x50, 0x34, 0xe0, 0xb1, 0x70, 0x63, 0x16, 0x7e,
					0x70, 0x16, 0xa5, 0x5c, 0xaa, 0x6f, 0xee, 0xca,
					0xd7, 0x32, 0xec, 0xe5, 0x6d, 0x63, 0x0f, 0x25,
					0x08, 0xc1, 0xa8, 0x84, 0xea, 0xcf, 0x71, 0x88,
				},
				WarnOnly: false,
			},
			11: {Expected: [32]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
				WarnOnly: false,
			}, 12: {Expected: [32]byte{
				0xa3, 0xc9, 0xd7, 0xd2, 0xb4, 0x0d, 0x36, 0x36,
				0xd1, 0xd1, 0x73, 0x26, 0x65, 0xeb, 0x36, 0x6f,
				0x1f, 0x1c, 0x5e, 0xed, 0x91, 0x31, 0x56, 0x88,
				0x43, 0x98, 0x4c, 0x20, 0xcd, 0x8d, 0xa4, 0x7a,
			},
				WarnOnly: false,
			}, 13: {Expected: [32]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
				WarnOnly: false,
			}, 14: {Expected: [32]byte{
				0xd7, 0xc4, 0xcc, 0x7f, 0xf7, 0x93, 0x30, 0x22,
				0xf0, 0x13, 0xe0, 0x3b, 0xde, 0xe8, 0x75, 0xb9,
				0x17, 0x20, 0xb5, 0xb8, 0x6c, 0xf1, 0x75, 0x3c,
				0xad, 0x83, 0x0f, 0x95, 0xe7, 0x91, 0x92, 0x6f,
			},
				WarnOnly: true,
			},
			15: {
				Expected: [32]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				WarnOnly: false,
			}}

	case cloudprovider.GCP:
		return M{
			1: {
				Expected: [32]byte{
					0x74, 0x5f, 0x2f, 0xb4, 0x23, 0x5e, 0x46, 0x47,
					0xaa, 0x0a, 0xd5, 0xac, 0xe7, 0x81, 0xcd, 0x92,
					0x9e, 0xb6, 0x8c, 0x28, 0x87, 0x0e, 0x7d, 0xd5,
					0xd1, 0xa1, 0x53, 0x58, 0x54, 0x32, 0x5e, 0x56,
				},
				WarnOnly: true,
			},
			2: {
				Expected: [32]byte{
					0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea,
					0x1f, 0x44, 0x3f, 0x15, 0x62, 0xbe, 0xec, 0x8d,
					0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f, 0xcf, 0x9a,
					0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69,
				},
				WarnOnly: true,
			},
			3: {
				Expected: [32]byte{
					0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea,
					0x1f, 0x44, 0x3f, 0x15, 0x62, 0xbe, 0xec, 0x8d,
					0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f, 0xcf, 0x9a,
					0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69,
				},
				WarnOnly: true,
			},
			4: {
				Expected: [32]byte{
					0xd3, 0xa0, 0x53, 0x1a, 0x16, 0xf8, 0xba, 0x3a,
					0x66, 0xc6, 0xd1, 0x9f, 0x39, 0x49, 0x7e, 0xb8,
					0x53, 0x8b, 0x7c, 0x1a, 0x93, 0xd2, 0x4f, 0x76,
					0x1f, 0x1b, 0xb7, 0xb1, 0xf9, 0x55, 0x20, 0x11,
				},
				WarnOnly: false,
			},
			6: {
				Expected: [32]byte{
					0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea,
					0x1f, 0x44, 0x3f, 0x15, 0x62, 0xbe, 0xec, 0x8d,
					0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f, 0xcf, 0x9a,
					0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69,
				},
				WarnOnly: true,
			},
			7: {
				Expected: [32]byte{
					0xb1, 0xe9, 0xb3, 0x05, 0x32, 0x5c, 0x51, 0xb9,
					0x3d, 0xa5, 0x8c, 0xbf, 0x7f, 0x92, 0x51, 0x2d,
					0x8e, 0xeb, 0xfa, 0x01, 0x14, 0x3e, 0x4d, 0x88,
					0x44, 0xe4, 0x0e, 0x06, 0x2e, 0x9b, 0x6c, 0xd5,
				},
				WarnOnly: true,
			},
			8: {
				Expected: [32]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				WarnOnly: false,
			},
			9: {
				Expected: [32]byte{
					0x11, 0x82, 0x07, 0xeb, 0x13, 0x00, 0x35, 0xb3,
					0x71, 0xc6, 0x86, 0xeb, 0x3f, 0x54, 0x31, 0x6b,
					0xa2, 0x1b, 0xfb, 0xd0, 0x07, 0x21, 0x94, 0x2f,
					0x0c, 0x3e, 0x5b, 0xf3, 0x8c, 0xaa, 0x91, 0x56,
				},
				WarnOnly: false,
			},
			11: {Expected: [32]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
				WarnOnly: false,
			}, 12: {Expected: [32]byte{
				0x8e, 0xb2, 0x9c, 0x45, 0x55, 0xa7, 0xf8, 0xdb,
				0xff, 0xd6, 0x4a, 0x1f, 0x08, 0x7a, 0x94, 0xb3,
				0xa1, 0xba, 0x31, 0x3d, 0x2b, 0x59, 0x4f, 0xe6,
				0xec, 0x4d, 0x71, 0x0f, 0x61, 0xb1, 0xfa, 0x38,
			},
				WarnOnly: false,
			}, 13: {Expected: [32]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
				WarnOnly: false,
			}, 14: {Expected: [32]byte{
				0xd7, 0xc4, 0xcc, 0x7f, 0xf7, 0x93, 0x30, 0x22,
				0xf0, 0x13, 0xe0, 0x3b, 0xde, 0xe8, 0x75, 0xb9,
				0x17, 0x20, 0xb5, 0xb8, 0x6c, 0xf1, 0x75, 0x3c,
				0xad, 0x83, 0x0f, 0x95, 0xe7, 0x91, 0x92, 0x6f,
			},
				WarnOnly: true,
			},
			15: {
				Expected: [32]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				WarnOnly: false,
			}}

	case cloudprovider.QEMU:
		return M{
			4: {
				Expected: [32]byte{
					0x9c, 0x6f, 0x57, 0xc0, 0xdd, 0x24, 0xb5, 0x46,
					0x8b, 0x1c, 0xa5, 0x7f, 0x7b, 0x69, 0xa1, 0x3c,
					0x2f, 0xfb, 0xf4, 0x43, 0xfd, 0xe9, 0xea, 0x59,
					0xf6, 0xb7, 0xe3, 0xbf, 0xec, 0xdc, 0xec, 0x5c,
				},
				WarnOnly: false,
			},
			8: {
				Expected: [32]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				WarnOnly: false,
			},
			9: {
				Expected: [32]byte{
					0x04, 0xb6, 0x7d, 0x41, 0xde, 0x6e, 0xe2, 0xd6,
					0xdc, 0x90, 0x37, 0xb2, 0x7a, 0xca, 0x64, 0x2d,
					0x9a, 0x97, 0xa3, 0xfe, 0x93, 0xee, 0xe1, 0x71,
					0xfe, 0x88, 0xfc, 0x88, 0x32, 0x18, 0x92, 0xc7,
				},
				WarnOnly: false,
			},
			11: {
				Expected: [32]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				WarnOnly: false,
			},
			12: {
				Expected: [32]byte{
					0xb6, 0x8d, 0x41, 0x06, 0x2c, 0x79, 0x19, 0xe3,
					0x35, 0x83, 0x06, 0x62, 0x35, 0xc6, 0x81, 0x1d,
					0xaa, 0xe6, 0xb2, 0x04, 0xbe, 0x74, 0x12, 0xcd,
					0x7d, 0x33, 0x20, 0x71, 0x5c, 0xc4, 0xb5, 0x5b,
				},
				WarnOnly: false,
			},
			13: {
				Expected: [32]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				WarnOnly: false,
			},
			15: {
				Expected: [32]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				WarnOnly: false,
			},
		}
	default:
		return nil
	}
}
