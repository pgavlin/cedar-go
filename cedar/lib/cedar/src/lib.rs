#![feature(vec_into_raw_parts)]
#![feature(min_specialization)]
#![feature(test)]

mod raw_string;
pub use raw_string::*;

mod diagnostics;
pub use diagnostics::*;

mod policy_set;
pub use policy_set::*;

mod schema;
pub use schema::*;

mod validator;
pub use validator::*;

mod authorizer;
pub use authorizer::*;

mod frontend;
pub use frontend::*;

#[cfg(test)]
mod tests {
    use serde_json::json;

    extern crate test;

    const all_policies: [&'static str; 5] = [
	r#"permit(
  principal == User::"alice", 
  action    == Action::"update", 
  resource  == Photo::"VacationPhoto94.jpg"
);
"#,
	r#"permit(
  principal == User::"bob",
  action    == Action::"update",
  resource  == Photo::"VacationPhoto95.jpg"
);
"#,
	r#"permit(
  principal == User::"chester",
  action    == Action::"update",
  resource  == Photo::"VacationPhoto96.jpg"
);
"#,
	r#"permit(
  principal == User::"dennis",
  action    == Action::"update",
  resource  == Photo::"VacationPhoto97.jpg"
);
"#,
	r#"permit(
  principal == User::"eric",
  action    == Action::"update",
  resource  == Photo::"VacationPhoto98.jpg"
);
"#,
    ];

    fn bench_is_authorized(policies: &[&str], b: &mut test::bench::Bencher) {
        let req = json!({
            "principal": r#"User::"alice""#,
            "action": r#"Action::"update""#,
            "resource": r#"Photo::"VacationPhoto94.jpg""#,
            "context": {},
            "slice": {
                "policies": policies.join("\n"),
                "entities": {},
            },
        }).to_string();

        b.iter(|| {
            cedar_policy::frontend::is_authorized::json_is_authorized(&req);
        });
    }

    #[bench]
    fn bench_is_authorized_1(b: &mut test::bench::Bencher) {
        bench_is_authorized(&all_policies[..1], b)
    }

    #[bench]
    fn bench_is_authorized_2(b: &mut test::bench::Bencher) {
        bench_is_authorized(&all_policies[..2], b)
    }

    #[bench]
    fn bench_is_authorized_3(b: &mut test::bench::Bencher) {
        bench_is_authorized(&all_policies[..3], b)
    }

    #[bench]
    fn bench_is_authorized_4(b: &mut test::bench::Bencher) {
        bench_is_authorized(&all_policies[..4], b)
    }

    #[bench]
    fn bench_is_authorized_5(b: &mut test::bench::Bencher) {
        bench_is_authorized(&all_policies[..5], b)
    }

    fn bench_authorizer(policies: &[&str], b: &mut test::bench::Bencher) {
        let req =cedar_policy::Request::new(
            Some(r#"User::"alice""#.parse().unwrap()),
            Some(r#"Action::"update""#.parse().unwrap()),
            Some(r#"Photo::"VacationPhoto94.jpg""#.parse().unwrap()),
            cedar_policy::Context::empty(),
        );
        let policy_set = policies.join("\n").parse().unwrap();
        let entities = cedar_policy::Entities::empty();
        let authorizer = cedar_policy::Authorizer::new();
        b.iter(|| {
            authorizer.is_authorized(&req, &policy_set, &entities);
        });            
    }

    #[bench]
    fn bench_authorizer_1(b: &mut test::bench::Bencher) {
        bench_authorizer(&all_policies[..1], b)
    }

    #[bench]
    fn bench_authorizer_2(b: &mut test::bench::Bencher) {
        bench_authorizer(&all_policies[..2], b)
    }

    #[bench]
    fn bench_authorizer_3(b: &mut test::bench::Bencher) {
        bench_authorizer(&all_policies[..3], b)
    }

    #[bench]
    fn bench_authorizer_4(b: &mut test::bench::Bencher) {
        bench_authorizer(&all_policies[..4], b)
    }

    #[bench]
    fn bench_authorizer_5(b: &mut test::bench::Bencher) {
        bench_authorizer(&all_policies[..5], b)
    }
}
