package cedar

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

var policies = []string{
	`permit(
  principal == User::"alice", 
  action    == Action::"update", 
  resource  == Photo::"VacationPhoto94.jpg"
);
`,
	`permit(
  principal == User::"bob",
  action    == Action::"update",
  resource  == Photo::"VacationPhoto95.jpg"
);
`,
	`permit(
  principal == User::"chester",
  action    == Action::"update",
  resource  == Photo::"VacationPhoto96.jpg"
);
`,
	`permit(
  principal == User::"dennis",
  action    == Action::"update",
  resource  == Photo::"VacationPhoto97.jpg"
);
`,
	`permit(
  principal == User::"eric",
  action    == Action::"update",
  resource  == Photo::"VacationPhoto98.jpg"
);
`,
}

func BenchmarkIsAuthorized(b *testing.B) {
	for i := 0; i < len(policies); i++ {
		policies := strings.Join(policies[:i+1], "\n")
		b.Run(fmt.Sprintf("%v policies", i+1), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				_, _, _, err := IsAuthorized(Request{
					Principal: `User::"alice"`,
					Action:    `Action::"update"`,
					Resource:  `Photo::"VacationPhoto94.jpg"`,
				}, policies, nil)
				require.NoError(b, err)
			}
		})
	}
}

func BenchmarkAuthorizer(b *testing.B) {
	for i := 0; i < len(policies); i++ {
		b.Run(fmt.Sprintf("%v policies", i+1), func(b *testing.B) {
			policies := strings.Join(policies[:i+1], "\n")

			policySet, diags := ParsePolicies(policies)
			require.Len(b, diags, 0)

			authorizer := NewAuthorizer()
			b.ResetTimer()

			for n := 0; n < b.N; n++ {
				_, _, _, err := authorizer.IsAuthorized(Request{
					Principal: `User::"alice"`,
					Action:    `Action::"update"`,
					Resource:  `Photo::"VacationPhoto94.jpg"`,
				}, policySet, nil)
				require.NoError(b, err)
			}
		})
	}
}

func BenchmarkAuthorizerImpl(b *testing.B) {
	for i := 0; i < len(policies); i++ {
		b.Run(fmt.Sprintf("%v policies", i+1), func(b *testing.B) {
			policies := strings.Join(policies[:i+1], "\n")

			policySet, diags := ParsePolicies(policies)
			require.Len(b, diags, 0)

			authorizer := NewAuthorizer()

			reqBytes, err := json.Marshal(Request{
				Principal: `User::"alice"`,
				Action:    `Action::"update"`,
				Resource:  `Photo::"VacationPhoto94.jpg"`,
			})
			require.NoError(b, err)

			cstring := make([]byte, len(reqBytes)+1)
			copy(cstring, reqBytes)
			cstring[len(cstring)-1] = 0

			var pinner runtime.Pinner
			defer pinner.Unpin()

			pinner.Pin(&cstring[0])

			b.ResetTimer()

			for n := 0; n < b.N; n++ {
				_, _ = authorizer.isAuthorized(unsafe.Pointer(&cstring[0]), policySet, nil)
			}
		})
	}
}
