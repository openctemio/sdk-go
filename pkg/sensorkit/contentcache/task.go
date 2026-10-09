package contentcache

import (
	"fmt"

	"github.com/openctemio/sdk-go/pkg/tool"
)

// Resolve sets the path of every pack a task names from the cache, acquiring
// each one for the task's lifetime: a path a job carried is replaced, never
// trusted. It fails, releasing what it took, when a pack is not held or is
// revoked; the caller runs the tool host with ContentRoot = Root() and calls
// the release when the task ends.
func (c *Cache) Resolve(task *tool.Task) (func(), error) {
	var releases []func()
	release := func() {
		for _, r := range releases {
			r()
		}
	}
	for i := range task.Content {
		for j := range task.Content[i].Packs {
			p := &task.Content[i].Packs[j]
			dir, rel, err := c.Acquire(p.Digest)
			if err != nil {
				release()
				return nil, fmt.Errorf("content slot %s: %w", task.Content[i].Slot, err)
			}
			releases = append(releases, rel)
			p.Path = dir
		}
	}
	return release, nil
}
