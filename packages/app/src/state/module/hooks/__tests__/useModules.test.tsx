/**
 * Copyright 2020 Opstrace, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import React from "react";
import { CombinedState } from "redux";
import { useDispatch, useSelector } from "react-redux";

import { renderHook } from "@testing-library/react-hooks";
import { StoreProvider } from "state/provider";
import getSubscriptionID from "state/utils/getSubscriptionID";
import { mainReducer } from "state/reducer";

import useModules, {
  getModules,
  getCurrentBranchModules,
  getMainBranchModules,
  getCombinedModules,
  getMainBranchModule,
  getCurrentBranchModule
} from "../useModules";
import { subscribe } from "../../actions";

jest.mock("react-redux", () => ({
  ...(jest.requireActual("react-redux") as object),
  useDispatch: jest.fn(),
  useSelector: jest.fn()
}));

jest.mock("state/utils/getSubscriptionID");

afterEach(() => {
  jest.clearAllMocks();
});

const mockAction = { type: "UNKNOWN_ACTION" } as any;

test("useModules hook", () => {
  const modules = [{ name: "test-module", branch_name: "test-branch" }];
  const dispatchMock = jest.fn();

  (useSelector as jest.Mock).mockReturnValueOnce(modules);
  (useDispatch as jest.Mock).mockReturnValueOnce(dispatchMock);
  (getSubscriptionID as jest.Mock).mockReturnValueOnce(10);

  const { result } = renderHook(() => useModules(), {
    wrapper: ({ children }: any) => <StoreProvider>{children}</StoreProvider>
  });

  expect(useSelector).toHaveBeenCalledWith(getCombinedModules);
  expect(dispatchMock).toHaveBeenCalledWith(subscribe(10));
  expect(result.current).toEqual(modules);
});

test("getModules selector", () => {
  const subState = {
    modules: { modules: [{ name: "test-module", branch_name: "test-branch" }] }
  };
  const state = mainReducer(subState as CombinedState<any>, mockAction);
  expect(getModules(state)).toEqual([
    { name: "test-module", branch_name: "test-branch" }
  ]);
});

describe("getCurrentBranchModules selector", () => {
  test("should find current branch modules", () => {
    const subState = {
      modules: {
        modules: [
          { name: "module-1", branch_name: "test-branch" },
          { name: "module-2", branch_name: "test-branch" },
          { name: "module-3", branch_name: "unknown-branch" }
        ]
      },
      branches: {
        currentBranchName: "test-branch",
        branches: [{ name: "test-branch", id: "branch-1" }]
      }
    };
    const state = mainReducer(subState as CombinedState<any>, mockAction);
    expect(getCurrentBranchModules(state)).toEqual([
      { name: "module-1", branch_name: "test-branch" },
      { name: "module-2", branch_name: "test-branch" }
    ]);
  });

  test("should not find current branch modules if its absent in store", () => {
    const subState = {
      modules: {
        modules: [{ name: "module-1", branch_name: "test-branch" }]
      },
      branches: {
        currentBranchName: "unknown-branch",
        branches: [{ name: "test-branch", id: "branch-1" }]
      }
    };
    const state = mainReducer(subState as CombinedState<any>, mockAction);
    expect(getCurrentBranchModules(state)).toBeNull();
  });
});

describe("getMainBranchModules selector", () => {
  test("should find main branch modules", () => {
    const subState = {
      modules: {
        modules: [
          { name: "module-1", branch_name: "main" },
          { name: "module-2", branch_name: "test-branch" },
          { name: "module-3", branch_name: "main" }
        ]
      }
    };
    const state = mainReducer(subState as CombinedState<any>, mockAction);
    expect(getMainBranchModules(state)).toEqual([
      { name: "module-1", branch_name: "main" },
      { name: "module-3", branch_name: "main" }
    ]);
  });

  test("should not find main branch modules if its absent in store", () => {
    const subState = {
      modules: {
        modules: [{ name: "module-1", branch_name: "test-branch" }]
      }
    };
    const state = mainReducer(subState as CombinedState<any>, mockAction);
    expect(getMainBranchModules(state)).toEqual([]);
  });
});

describe("getCombinedModules selector", () => {
  test("should find main branch modules and current branch modules", () => {
    const subState = {
      modules: {
        modules: [
          { name: "module-1", branch_name: "main" },
          { name: "module-2", branch_name: "test-branch" },
          { name: "module-3", branch_name: "unknown-branch" }
        ]
      },
      branches: {
        currentBranchName: "test-branch",
        branches: [{ name: "test-branch", id: "branch-1" }]
      }
    };
    const state = mainReducer(subState as CombinedState<any>, mockAction);
    expect(getCombinedModules(state)).toEqual([
      { name: "module-2", branch_name: "test-branch" },
      { name: "module-1", branch_name: "main" }
    ]);
  });

  test("should not find main branch modules and current branch modules if branches list is empty", () => {
    const subState = {
      modules: {
        modules: [
          { name: "module-1", branch_name: "main" },
          { name: "module-2", branch_name: "test-branch" }
        ]
      },
      branches: {
        currentBranchName: "test-branch",
        branches: []
      }
    };
    const state = mainReducer(subState as CombinedState<any>, mockAction);
    expect(getCombinedModules(state)).toBeNull();
  });

  test("should not find main branch modules and current branch modules if its absent in store", () => {
    const subState = {
      modules: {
        modules: [{ name: "module-1", branch_name: "unknown-branch" }]
      },
      branches: { currentBranchName: "test-branch" }
    };
    const state = mainReducer(subState as CombinedState<any>, mockAction);
    expect(getMainBranchModules(state)).toEqual([]);
  });
});

describe("getCombinedModules selector", () => {
  test("should find module", () => {
    const subState = {
      modules: {
        modules: [
          { name: "test-1", branch_name: "main", scope: "/foo" },
          { name: "test-2", branch_name: "main", scope: "/foo" },
          { name: "test-2", branch_name: "test-branch", scope: "/foo" }
        ]
      }
    };
    const state = mainReducer(subState as CombinedState<any>, mockAction);
    expect(getMainBranchModule("test-2", "/foo")(state)).toEqual({
      name: "test-2",
      branch_name: "main",
      scope: "/foo"
    });
  });

  test("should not find module if its absent in store", () => {
    const subState = {
      modules: {
        modules: [
          { name: "test-1", branch_name: "test-branch", scope: "/foo" },
          { name: "test-1", branch_name: "main", scope: "/" }
        ]
      }
    };
    const state = mainReducer(subState as CombinedState<any>, mockAction);
    expect(getMainBranchModule("test-1", "/foo")(state)).toBeUndefined();
  });
});

describe("getCurrentBranchModule selector", () => {
  test("should find module", () => {
    const subState = {
      modules: {
        modules: [
          { name: "test-1", branch_name: "main", scope: "/foo" },
          { name: "test-2", branch_name: "main", scope: "/foo" },
          { name: "test-2", branch_name: "test-branch", scope: "/foo" }
        ]
      },
      branches: {
        currentBranchName: "test-branch",
        branches: [{ name: "test-branch", id: "branch-1" }]
      }
    };
    const state = mainReducer(subState as CombinedState<any>, mockAction);
    expect(getCurrentBranchModule("test-2", "/foo")(state)).toEqual({
      name: "test-2",
      branch_name: "test-branch",
      scope: "/foo"
    });
  });

  test("should not find module if its absent in store", () => {
    const subState = {
      modules: {
        modules: [
          { name: "test-1", branch_name: "test-branch", scope: "/foo" },
          { name: "test-1", branch_name: "main", scope: "/" }
        ]
      },
      branches: { currentBranchName: "test-branch", branches: [] }
    };
    const state = mainReducer(subState as CombinedState<any>, mockAction);
    expect(getCurrentBranchModule("test-1", "/")(state)).toBeUndefined();
  });
});
