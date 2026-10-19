package akv1

// Red-team: a vault member forges profile attribution (spec §5.1). It
// relabels a field to another device, backdates a change, or rewrites
// provenance of a field it did not change. CheckProfileProvenance must drop
// each forged field while the record and every honest field still apply, and
// must show nothing as this device's own unless it can check it.

import (
	"reflect"
	"testing"
)

var (
	ppSelf      = fixedID(0xA1) // this device
	ppAuthor    = fixedID(0xB2) // the record's author
	ppBystander = fixedID(0xC3)
)

func ppField(v any, by string, at int64, src string) ProfileField {
	return ProfileField{Value: v, By: by, At: at, Src: src}
}

func ppRecord(author string, ts, base int64) SignedRecord {
	return SignedRecord{Author: author, TS: ts, BaseRevision: base}
}

func TestRedTeamProfileProvenance(t *testing.T) {
	prev := Profile{
		"provider": ppField("stripe", ppSelf, 100, ProfileSrcLocal),
		"tags":     ppField([]string{"billing", "live"}, ppBystander, 90, ProfileSrcImport),
	}
	rec := ppRecord(ppAuthor, 500, 3)

	cases := []struct {
		name    string
		next    Profile
		dropped []string
	}{
		{"honest change and unchanged fields", Profile{
			"provider": prev["provider"], "tags": prev["tags"],
			"environment": ppField("prod", ppAuthor, 500, ProfileSrcLocal),
		}, []string{}},
		{"changed field attributed to another device", Profile{
			"environment": ppField("prod", ppSelf, 500, ProfileSrcLocal),
		}, []string{"environment"}},
		{"changed field backdated", Profile{
			"environment": ppField("prod", ppAuthor, 499, ProfileSrcLocal),
		}, []string{"environment"}},
		{"unchanged field relabelled to the author", Profile{
			"provider": ppField("stripe", ppAuthor, 500, ProfileSrcLocal),
		}, []string{"provider"}},
		{"unchanged field with a rewritten src", Profile{
			"provider": ppField("stripe", ppSelf, 100, ProfileSrcImport),
		}, []string{"provider"}},
		{"unchanged list relabelled", Profile{
			"tags": ppField([]string{"billing", "live"}, ppSelf, 90, ProfileSrcImport),
		}, []string{"tags"}},
		{"reordered list is a change by the author", Profile{
			"tags": ppField([]string{"live", "billing"}, ppAuthor, 500, ProfileSrcLocal),
		}, []string{}},
		{"reordered list keeping the old attribution", Profile{
			"tags": ppField([]string{"live", "billing"}, ppBystander, 90, ProfileSrcImport),
		}, []string{"tags"}},
	}
	for _, c := range cases {
		got := CheckProfileProvenance(prev, c.next, rec, ppSelf)
		if !reflect.DeepEqual(got.Dropped, c.dropped) {
			t.Errorf("%s: dropped %v, want %v", c.name, got.Dropped, c.dropped)
		}
		if len(got.Profile)+len(got.Dropped) != len(c.next) {
			t.Errorf("%s: kept and dropped do not cover next", c.name)
		}
	}

	// Only a field this device wrote and could check shows as its own.
	got := CheckProfileProvenance(prev, Profile{"provider": prev["provider"], "tags": prev["tags"]}, rec, ppSelf)
	if got.Origins["provider"] != ProfileSrcLocal || got.Origins["tags"] != ProfileOriginSync {
		t.Errorf("origins %v", got.Origins)
	}
}

func TestRedTeamProfileProvenanceWithoutPrev(t *testing.T) {
	next := Profile{
		"provider": ppField("stripe", ppSelf, 1, ProfileSrcLocal), // claims to be this device's
		"tags":     ppField([]string{"x"}, ppBystander, 2, ProfileSrcImport),
	}
	got := CheckProfileProvenance(nil, next, ppRecord(ppAuthor, 500, 7), ppSelf)
	if len(got.Dropped) != 0 || len(got.Profile) != 2 {
		t.Fatalf("prev null keeps every field: %+v", got)
	}
	for k, o := range got.Origins {
		if o != ProfileOriginSync {
			t.Errorf("%s shown as %s; an unchecked field is sync", k, o)
		}
	}
	// A record this device wrote shows its own fields as its own.
	own := CheckProfileProvenance(nil, Profile{"provider": ppField("stripe", ppSelf, 500, ProfileSrcLocal)}, ppRecord(ppSelf, 500, 7), ppSelf)
	if own.Origins["provider"] != ProfileSrcLocal {
		t.Errorf("own record origin %v", own.Origins)
	}
}

func TestRedTeamProfileProvenanceCreate(t *testing.T) {
	// A create (base_revision 0) is checked against an empty profile even if
	// the caller passes none: every field must be by the author at record ts.
	next := Profile{
		"provider": ppField("stripe", ppAuthor, 500, ProfileSrcLocal),
		"owner":    ppField("ops", ppSelf, 500, ProfileSrcLocal),
	}
	got := CheckProfileProvenance(nil, next, ppRecord(ppAuthor, 500, 0), ppSelf)
	if !reflect.DeepEqual(got.Dropped, []string{"owner"}) {
		t.Errorf("create dropped %v", got.Dropped)
	}
	if got.Origins["provider"] != ProfileOriginSync {
		t.Errorf("another author's field is sync, got %v", got.Origins["provider"])
	}
}
